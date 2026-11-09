package com.rante.login;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * A local OpenID provider for the tests, shaped like Rante Login: discovery, JWKS, token and userinfo endpoints on
 * 127.0.0.1. It issues codes that the tests hand it (standing in for the authorize step), checks each token request
 * (PKCE, redirect URI, client authentication, single-use assertions) and signs ID tokens with a key generated for the
 * run.
 */
final class LocalIdp implements AutoCloseable {
    private static final String ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    record SigningKey(String kid, RSAPrivateKey privateKey, RSAKey jwk) {
    }

    record IssuedCode(String clientId, String redirectUri, String codeChallenge, String nonce, Map<String, Object> claims) {
    }

    record Recorded(String method, String path, Map<String, String> form, String authorization) {
    }

    private final HttpServer server;
    final String origin;
    final String issuer;
    final String authorizationEndpoint;
    final String tokenEndpoint;
    volatile String discoveryIssuer;
    final List<SigningKey> signingKeys = new CopyOnWriteArrayList<>();
    final List<Recorded> requests = new CopyOnWriteArrayList<>();
    private final Map<String, String> clientTypes = new ConcurrentHashMap<>();
    private final Map<String, Map<String, PublicKey>> clientKeys = new ConcurrentHashMap<>();
    private final Map<String, IssuedCode> codes = new ConcurrentHashMap<>();
    private final Map<String, Map<String, Object>> accessTokens = new ConcurrentHashMap<>();
    private final Set<String> usedAssertions = ConcurrentHashMap.newKeySet();
    volatile SignedJWT lastAssertion;

    LocalIdp() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        origin = "http://127.0.0.1:" + server.getAddress().getPort();
        issuer = origin + "/common/v2.0";
        authorizationEndpoint = origin + "/common/oauth2/v2.0/authorize";
        tokenEndpoint = origin + "/common/oauth2/v2.0/token";
        discoveryIssuer = issuer;
        addSigningKey("test-key-1");
        server.createContext("/", this::handle);
        server.start();
    }

    @Override
    public void close() {
        server.stop(0);
    }

    SigningKey addSigningKey(String kid) throws Exception {
        KeyPair pair = rsaKeyPair();
        SigningKey key = new SigningKey(kid, (RSAPrivateKey) pair.getPrivate(),
                new RSAKey.Builder((RSAPublicKey) pair.getPublic()).keyID(kid).algorithm(JWSAlgorithm.RS256)
                        .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE).build());
        signingKeys.add(key);
        return key;
    }

    static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    /** type is Web (keys: prefix to public key) or BrowserOnly. */
    void registerClient(String clientId, String type, Map<String, PublicKey> keys) {
        clientTypes.put(clientId, type);
        clientKeys.put(clientId, keys == null ? Map.of() : keys);
    }

    /** Stands in for the authorize step: a code for these values. */
    String issueCode(String clientId, String redirectUri, String codeChallenge, String nonce, Map<String, Object> claims) {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        String code = HexFormat.of().formatHex(bytes);
        codes.put(code, new IssuedCode(clientId, redirectUri, codeChallenge, nonce, claims));
        return code;
    }

    /** An ID token like Rante Login's. Override any claim (null removes it), or sign with another key and kid. */
    String mintIdToken(Map<String, Object> claims, RSAPrivateKey key, String kid) throws Exception {
        long now = System.currentTimeMillis() / 1000;
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", issuer);
        payload.put("sub", "pairwise-subject-1");
        payload.put("iat", now);
        payload.put("exp", now + 600);
        payload.put("auth_time", now);
        payload.putAll(claims);
        payload.values().removeIf(value -> value == null);
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).type(JOSEObjectType.JWT).build(),
                JWTClaimsSet.parse(payload));
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    String mintIdToken(Map<String, Object> claims) throws Exception {
        return mintIdToken(claims, signingKeys.get(0).privateKey(), signingKeys.get(0).kid());
    }

    private void handle(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            Map<String, String> form = new HashMap<>();
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            for (String pair : body.split("&")) {
                int index = pair.indexOf('=');
                if (index > 0) {
                    form.put(URLDecoder.decode(pair.substring(0, index), StandardCharsets.UTF_8),
                            URLDecoder.decode(pair.substring(index + 1), StandardCharsets.UTF_8));
                }
            }
            requests.add(new Recorded(exchange.getRequestMethod(), path, form, exchange.getRequestHeaders().getFirst("Authorization")));
            switch (exchange.getRequestMethod() + " " + path) {
                case "GET /common/v2.0/.well-known/openid-configuration" -> send(exchange, 200, "{"
                        + "\"issuer\":\"" + discoveryIssuer + "\","
                        + "\"authorization_endpoint\":\"" + authorizationEndpoint + "\","
                        + "\"token_endpoint\":\"" + tokenEndpoint + "\","
                        + "\"userinfo_endpoint\":\"" + origin + "/common/oidc/v2.0/userinfo\","
                        + "\"jwks_uri\":\"" + origin + "/common/discovery/v2.0/keys\","
                        + "\"response_types_supported\":[\"code\"],\"subject_types_supported\":[\"pairwise\"],"
                        + "\"id_token_signing_alg_values_supported\":[\"RS256\"],"
                        + "\"token_endpoint_auth_methods_supported\":[\"private_key_jwt\",\"none\"],"
                        + "\"code_challenge_methods_supported\":[\"S256\"],"
                        + "\"authorization_response_iss_parameter_supported\":true}");
                case "GET /common/discovery/v2.0/keys" -> send(exchange, 200,
                        new JWKSet(signingKeys.stream().map(key -> (com.nimbusds.jose.jwk.JWK) key.jwk()).toList()).toString(true));
                case "POST /common/oauth2/v2.0/token" -> token(exchange, form);
                case "GET /common/oidc/v2.0/userinfo" -> userinfo(exchange);
                default -> send(exchange, 404, "{}");
            }
        } catch (Exception error) {
            send(exchange, 500, "{\"error\":\"server_error\"}");
        }
    }

    private void token(HttpExchange exchange, Map<String, String> form) throws Exception {
        String clientId = form.getOrDefault("client_id", "");
        String type = clientTypes.get(clientId);
        if (type == null || form.containsKey("client_secret") || exchange.getRequestHeaders().containsKey("Authorization")) {
            refuse(exchange, 401, "invalid_client");
            return;
        }
        if (type.equals("Web")) {
            if (!ASSERTION_TYPE.equals(form.get("client_assertion_type")) || form.get("client_assertion") == null) {
                refuse(exchange, 401, "invalid_client");
                return;
            }
            SignedJWT assertion = SignedJWT.parse(form.get("client_assertion"));
            PublicKey key = clientKeys.get(clientId).get(assertion.getHeader().getKeyID());
            JWTClaimsSet claims = assertion.getJWTClaimsSet();
            JWSVerifier verifier = key instanceof RSAPublicKey rsa ? new RSASSAVerifier(rsa) : key instanceof ECPublicKey ec ? new ECDSAVerifier(ec) : null;
            long lifetime = claims.getExpirationTime() == null || claims.getIssueTime() == null ? Long.MAX_VALUE
                    : claims.getExpirationTime().getTime() - claims.getIssueTime().getTime();
            if (verifier == null || !assertion.verify(verifier) || !clientId.equals(claims.getIssuer()) || !clientId.equals(claims.getSubject())
                    || !claims.getAudience().equals(List.of(tokenEndpoint)) || claims.getExpirationTime().before(new Date())
                    || lifetime > 300_000 || claims.getJWTID() == null || !usedAssertions.add(claims.getJWTID())) {
                refuse(exchange, 401, "invalid_client");
                return;
            }
            lastAssertion = assertion;
        } else if (form.containsKey("client_assertion") || form.containsKey("client_assertion_type")) {
            refuse(exchange, 401, "invalid_client");
            return;
        }
        IssuedCode issued = codes.remove(form.getOrDefault("code", ""));
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(form.getOrDefault("code_verifier", "").getBytes(StandardCharsets.US_ASCII)));
        if (issued == null || !issued.clientId().equals(clientId) || !issued.redirectUri().equals(form.get("redirect_uri"))
                || !issued.codeChallenge().equals(challenge)) {
            refuse(exchange, 400, "invalid_grant");
            return;
        }
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("aud", clientId);
        claims.put("azp", clientId);
        claims.put("nonce", issued.nonce());
        claims.putAll(issued.claims());
        String accessToken = UUID.randomUUID().toString();
        accessTokens.put(accessToken, Map.of("sub", issued.claims().get("sub"), "name", issued.claims().get("name")));
        send(exchange, 200, "{\"access_token\":\"" + accessToken + "\",\"token_type\":\"Bearer\",\"expires_in\":900,"
                + "\"id_token\":\"" + mintIdToken(claims) + "\",\"scope\":\"openid profile email\"}");
    }

    private void userinfo(HttpExchange exchange) throws IOException {
        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        Map<String, Object> claims = authorization != null && authorization.startsWith("Bearer ")
                ? accessTokens.get(authorization.substring(7)) : null;
        if (claims == null) {
            exchange.getResponseHeaders().add("WWW-Authenticate", "Bearer error=\"invalid_token\"");
            send(exchange, 401, "{}");
            return;
        }
        send(exchange, 200, "{\"sub\":\"" + claims.get("sub") + "\",\"name\":\"" + claims.get("name") + "\"}");
    }

    private static void refuse(HttpExchange exchange, int status, String error) throws IOException {
        send(exchange, status, "{\"error\":\"" + error + "\",\"error_description\":\"test IdP: " + error + "\"}");
    }

    private static void send(HttpExchange exchange, int status, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    static Map<String, String> query(String url) {
        Map<String, String> values = new LinkedHashMap<>();
        String query = java.net.URI.create(url).getRawQuery();
        for (String pair : query.split("&")) {
            int index = pair.indexOf('=');
            values.put(URLDecoder.decode(pair.substring(0, index), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(index + 1), StandardCharsets.UTF_8));
        }
        return values;
    }

    static List<String> sorted(Set<String> names) {
        List<String> list = new ArrayList<>(new HashSet<>(names));
        list.sort(String::compareTo);
        return list;
    }
}
