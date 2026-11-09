package com.rante.login;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class RanteLoginClientTest {
    private static final String WEB_CLIENT = "11111111-2222-4333-8444-555555555555";
    private static final String BROWSER_CLIENT = "66666666-7777-4888-9999-aaaaaaaaaaaa";
    // The fake key prefixes, split so secret scanners don't take them for Stripe restricted keys (rk_live_ + 24 characters).
    private static final String RSA_PREFIX = "rk_live_" + "0123456789abcdef01234567";
    private static final String EC_PREFIX = "rk_live_" + "89abcdef0123456789abcdef";
    private static final String REDIRECT_URI = "http://localhost:3000/auth/rante/callback";
    private static final String NONCE = "expected-nonce";

    private static LocalIdp idp;
    private static KeyPair rsa;
    private static KeyPair ec;

    @BeforeAll
    static void start() throws Exception {
        idp = new LocalIdp();
        rsa = LocalIdp.rsaKeyPair();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        ec = generator.generateKeyPair();
        idp.registerClient(WEB_CLIENT, "Web", Map.of(RSA_PREFIX, rsa.getPublic(), EC_PREFIX, ec.getPublic()));
        idp.registerClient(BROWSER_CLIENT, "BrowserOnly", null);
    }

    @AfterAll
    static void stop() {
        idp.close();
    }

    private static RanteLoginClient webClient(RanteLoginSigningKey key) {
        return RanteLoginClient.builder().clientId(WEB_CLIENT).redirectUri(REDIRECT_URI).issuer(idp.issuer)
                .signingKey(key == null ? RanteLoginSigningKey.fromPrivateKey(RSA_PREFIX, rsa.getPrivate()) : key).build();
    }

    // The authorize step, as the test IdP sees it: a code bound to the request's PKCE challenge and nonce.
    private static String authorize(AuthorizationRequest request, String clientId) {
        Map<String, String> query = LocalIdp.query(request.url());
        return idp.issueCode(clientId, query.get("redirect_uri"), query.get("code_challenge"), query.get("nonce"),
                Map.of("sub", "pairwise-subject-1", "name", "Test Person"));
    }

    private static String callback(String code, String state, String iss) {
        StringBuilder query = new StringBuilder();
        for (String[] pair : new String[][] {{"code", code}, {"state", state}, {"iss", iss}}) {
            if (pair[1] != null) {
                query.append(query.length() == 0 ? "" : "&").append(pair[0]).append('=').append(URLEncoder.encode(pair[1], StandardCharsets.UTF_8));
            }
        }
        return query.toString();
    }

    private static RanteLoginException fails(String code, Runnable call) {
        RanteLoginException error = assertThrows(RanteLoginException.class, call::run);
        assertEquals(code, error.code(), error.getMessage());
        return error;
    }

    private static Map<String, String> lastTokenForm() {
        List<LocalIdp.Recorded> tokens = idp.requests.stream().filter(r -> r.path().endsWith("/token")).toList();
        return tokens.get(tokens.size() - 1).form();
    }

    @Test
    void createAuthorizationRequestBuildsTheUrlWithPkceS256StateAndNonce() throws Exception {
        AuthorizationRequest request = webClient(null).createAuthorizationRequest();
        URI url = URI.create(request.url());
        assertEquals(idp.authorizationEndpoint, url.getScheme() + "://" + url.getRawAuthority() + url.getRawPath());
        Map<String, String> query = LocalIdp.query(request.url());
        assertEquals(List.of("client_id", "code_challenge", "code_challenge_method", "nonce", "redirect_uri", "response_type", "scope", "state"),
                LocalIdp.sorted(query.keySet()));
        assertEquals(WEB_CLIENT, query.get("client_id"));
        assertEquals("code", query.get("response_type"));
        assertEquals(REDIRECT_URI, query.get("redirect_uri"));
        assertEquals("openid profile email", query.get("scope"));
        assertEquals("S256", query.get("code_challenge_method"));
        String challenge = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(request.codeVerifier().getBytes(StandardCharsets.US_ASCII)));
        assertEquals(challenge, query.get("code_challenge"));
        assertEquals(request.state(), query.get("state"));
        assertEquals(request.nonce(), query.get("nonce"));
        assertEquals(43, request.codeVerifier().length());
        AuthorizationRequest other = webClient(null).createAuthorizationRequest();
        assertNotEquals(request.state(), other.state());
        assertNotEquals(request.nonce(), other.nonce());
        assertNotEquals(request.codeVerifier(), other.codeVerifier());
    }

    @Test
    void createAuthorizationRequestPassesOptionsAndRefusesBadOnes() {
        RanteLoginClient client = webClient(null);
        AuthorizationRequest request = client.createAuthorizationRequest(new AuthorizationRequestOptions("server-nonce-1", "login", "person@example.com", 0));
        Map<String, String> query = LocalIdp.query(request.url());
        assertEquals("server-nonce-1", request.nonce());
        assertEquals("server-nonce-1", query.get("nonce"));
        assertEquals("login", query.get("prompt"));
        assertEquals("person@example.com", query.get("login_hint"));
        assertEquals("0", query.get("max_age"));
        fails("invalid_request", () -> client.createAuthorizationRequest(new AuthorizationRequestOptions("has space", null, null, null)));
        fails("invalid_request", () -> client.createAuthorizationRequest(new AuthorizationRequestOptions(null, "none login", null, null)));
        fails("invalid_request", () -> client.createAuthorizationRequest(new AuthorizationRequestOptions(null, "always", null, null)));
        fails("invalid_request", () -> client.createAuthorizationRequest(new AuthorizationRequestOptions(null, null, null, -1)));
    }

    @Test
    void serverSideWebsiteSignsInWithAPrivateKeyJwtRs256Assertion() throws Exception {
        RanteLoginClient client = webClient(null);
        assertEquals("private_key_jwt", client.clientAuthentication());
        AuthorizationRequest request = client.createAuthorizationRequest();
        String code = authorize(request, WEB_CLIENT);
        RanteLoginResult result = client.handleCallback(URI.create(REDIRECT_URI + "?" + callback(code, request.state(), idp.issuer)), request.toExpected());
        assertEquals("pairwise-subject-1", result.subject());
        assertEquals("Test Person", result.claims().get("name"));
        assertEquals(request.nonce(), result.claims().get("nonce"));
        assertEquals("Bearer", result.tokens().tokenType());
        assertNotNull(result.accessToken());

        Map<String, String> form = lastTokenForm();
        assertEquals("authorization_code", form.get("grant_type"));
        assertEquals(REDIRECT_URI, form.get("redirect_uri"));
        assertEquals(request.codeVerifier(), form.get("code_verifier"));
        assertEquals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", form.get("client_assertion_type"));
        SignedJWT assertion = idp.lastAssertion;
        assertEquals("RS256", assertion.getHeader().getAlgorithm().getName());
        assertEquals(RSA_PREFIX, assertion.getHeader().getKeyID());
        assertEquals(WEB_CLIENT, assertion.getJWTClaimsSet().getIssuer());
        assertEquals(WEB_CLIENT, assertion.getJWTClaimsSet().getSubject());
        assertEquals(List.of(idp.tokenEndpoint), assertion.getJWTClaimsSet().getAudience());
        assertTrue(assertion.getJWTClaimsSet().getExpirationTime().getTime() - assertion.getJWTClaimsSet().getIssueTime().getTime() <= 300_000);
        assertNotNull(assertion.getJWTClaimsSet().getJWTID());
    }

    @Test
    void es256KeysSignEs256Assertions() {
        RanteLoginClient client = webClient(RanteLoginSigningKey.fromPrivateKey(EC_PREFIX, ec.getPrivate()));
        AuthorizationRequest request = client.createAuthorizationRequest();
        RanteLoginResult result = client.handleCallback(callback(authorize(request, WEB_CLIENT), request.state(), idp.issuer), request.toExpected());
        assertEquals("pairwise-subject-1", result.subject());
        assertEquals("ES256", idp.lastAssertion.getHeader().getAlgorithm().getName());
        assertEquals(EC_PREFIX, idp.lastAssertion.getHeader().getKeyID());
    }

    @Test
    void browserOnlyWebsiteSendsNoClientCredential() {
        RanteLoginClient client = RanteLoginClient.builder().clientId(BROWSER_CLIENT).redirectUri(REDIRECT_URI).issuer(idp.issuer).build();
        assertEquals("none", client.clientAuthentication());
        AuthorizationRequest request = client.createAuthorizationRequest();
        Map<String, List<String>> query = Map.of("code", List.of(authorize(request, BROWSER_CLIENT)), "state", List.of(request.state()),
                "iss", List.of(idp.issuer));
        RanteLoginResult result = client.handleCallback(query, new ExpectedTransaction(request.state(), request.nonce(), request.codeVerifier()));
        assertEquals(List.of(BROWSER_CLIENT), result.claims().get("aud") instanceof List<?> list ? list : List.of(result.claims().get("aud")));
        Map<String, String> form = lastTokenForm();
        assertFalse(form.containsKey("client_assertion"));
        assertFalse(form.containsKey("client_assertion_type"));
        assertFalse(form.containsKey("client_secret"));
    }

    @Test
    void refusesBadResponsesBeforeAnyTokenRequest() {
        RanteLoginClient client = webClient(null);
        AuthorizationRequest request = client.createAuthorizationRequest();
        String code = authorize(request, WEB_CLIENT);
        int before = idp.requests.size();
        fails("state_mismatch", () -> client.handleCallback(callback(code, "another", idp.issuer), request.toExpected()));
        fails("issuer_mismatch", () -> client.handleCallback(callback(code, request.state(), null), request.toExpected()));
        fails("issuer_mismatch", () -> client.handleCallback(callback(code, request.state(), "https://login.example.com/common/v2.0"), request.toExpected()));
        fails("invalid_request", () -> client.handleCallback(callback(code, request.state(), idp.issuer) + "&state=" + request.state(), request.toExpected()));
        fails("missing_transaction", () -> client.handleCallback(callback(code, request.state(), idp.issuer), null));
        fails("missing_transaction", () -> client.handleCallback(callback(code, request.state(), idp.issuer), new ExpectedTransaction(request.state(), null, null)));
        fails("invalid_request", () -> client.handleCallback(callback(null, request.state(), idp.issuer), request.toExpected()));
        assertEquals(before, idp.requests.size());
    }

    @Test
    void reportsTheProvidersError() {
        RanteLoginClient client = webClient(null);
        AuthorizationRequest request = client.createAuthorizationRequest();
        RanteLoginException error = fails("access_denied", () -> client.handleCallback("error=access_denied&error_description="
                + URLEncoder.encode("The person cancelled the sign-in.", StandardCharsets.UTF_8) + "&state=" + request.state()
                + "&iss=" + URLEncoder.encode(idp.issuer, StandardCharsets.UTF_8), request.toExpected()));
        assertEquals("The person cancelled the sign-in.", error.getMessage());
    }

    @Test
    void tokenEndpointErrorsKeepTheirCodeAndStatus() {
        RanteLoginClient client = webClient(null);
        AuthorizationRequest request = client.createAuthorizationRequest();
        String query = callback(authorize(request, WEB_CLIENT), request.state(), idp.issuer);
        client.handleCallback(query, request.toExpected());
        assertEquals(400, fails("invalid_grant", () -> client.handleCallback(query, request.toExpected())).status());
    }

    @Test
    void aKeyThatIsNotLinkedToTheAppGetsInvalidClient() throws Exception {
        RanteLoginClient client = webClient(RanteLoginSigningKey.fromPrivateKey("rk_live_" + "f".repeat(24), LocalIdp.rsaKeyPair().getPrivate()));
        AuthorizationRequest request = client.createAuthorizationRequest();
        assertEquals(401, fails("invalid_client", () -> client.handleCallback(callback(authorize(request, WEB_CLIENT), request.state(), idp.issuer),
                request.toExpected())).status());
    }

    private static String valid(Map<String, Object> overrides) throws Exception {
        Map<String, Object> claims = new HashMap<>(Map.of("aud", WEB_CLIENT, "azp", WEB_CLIENT, "nonce", NONCE));
        claims.putAll(overrides);
        return idp.mintIdToken(claims);
    }

    @Test
    void validateIdTokenAcceptsAValidToken() throws Exception {
        ValidatedIdToken token = webClient(null).validateIdToken(valid(Map.of("name", "Test Person")), NONCE);
        assertEquals("pairwise-subject-1", token.subject());
        assertEquals("Test Person", token.claims().get("name"));
    }

    @Test
    void validateIdTokenRefusesTokensThatFailAnyCheck() throws Exception {
        RanteLoginClient client = webClient(null);
        long now = System.currentTimeMillis() / 1000;
        RSAPrivateKey stranger = (RSAPrivateKey) LocalIdp.rsaKeyPair().getPrivate();
        Map<String, Object> body = new LinkedHashMap<>(Map.of("iss", idp.issuer, "sub", "s", "aud", WEB_CLIENT, "azp", WEB_CLIENT,
                "iat", now, "exp", now + 600, "nonce", NONCE));
        String json = "{" + String.join(",", body.entrySet().stream().map(e -> "\"" + e.getKey() + "\":"
                + (e.getValue() instanceof String ? "\"" + e.getValue() + "\"" : e.getValue())).toList()) + "}";
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String hsInput = b64.encodeToString("{\"alg\":\"HS256\",\"kid\":\"test-key-1\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8))
                + "." + b64.encodeToString(json.getBytes(StandardCharsets.UTF_8));
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec("a-secret-of-thirty-two-bytes-!!!".getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        String hs256 = hsInput + "." + b64.encodeToString(mac.doFinal(hsInput.getBytes(StandardCharsets.US_ASCII)));
        String none = b64.encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8)) + "."
                + b64.encodeToString(json.getBytes(StandardCharsets.UTF_8)) + ".";
        Map<String, Object> noAzp = new HashMap<>();
        noAzp.put("aud", "99999999-2222-4333-8444-555555555555");
        noAzp.put("azp", null);
        Map<String, Object> noNonce = new HashMap<>();
        noNonce.put("nonce", null);
        Map<String, Object> noSub = new HashMap<>();
        noSub.put("sub", null);
        Map<String, Supplier<String>> cases = new LinkedHashMap<>();
        cases.put("another key, same kid", () -> unchecked(() -> idp.mintIdToken(Map.of("aud", WEB_CLIENT, "nonce", NONCE), stranger, "test-key-1")));
        cases.put("unknown kid", () -> unchecked(() -> idp.mintIdToken(Map.of("aud", WEB_CLIENT, "nonce", NONCE), stranger, "not-a-rante-key")));
        cases.put("another issuer", () -> unchecked(() -> valid(Map.of("iss", "https://login.example.com/common/v2.0"))));
        cases.put("another audience", () -> unchecked(() -> valid(noAzp)));
        cases.put("another azp", () -> unchecked(() -> valid(Map.of("azp", "99999999-2222-4333-8444-555555555555"))));
        cases.put("expired", () -> unchecked(() -> valid(Map.of("iat", now - 1200, "exp", now - 600))));
        cases.put("another nonce", () -> unchecked(() -> valid(Map.of("nonce", "other-nonce"))));
        cases.put("no nonce", () -> unchecked(() -> valid(noNonce)));
        cases.put("no sub", () -> unchecked(() -> valid(noSub)));
        cases.put("HS256", () -> hs256);
        cases.put("alg none", () -> none);
        cases.put("not a JWT", () -> "not-a-jwt");
        for (Map.Entry<String, Supplier<String>> entry : cases.entrySet()) {
            String token = entry.getValue().get();
            RanteLoginException error = assertThrows(RanteLoginException.class, () -> client.validateIdToken(token, NONCE), entry.getKey());
            assertEquals("invalid_id_token", error.code(), entry.getKey() + ": " + error.getMessage());
        }
        fails("invalid_request", () -> client.validateIdToken(unchecked(() -> valid(Map.of())), ""));
    }

    @Test
    void validateIdTokenAllowsAMinuteOfClockSkew() throws Exception {
        long now = System.currentTimeMillis() / 1000;
        webClient(null).validateIdToken(valid(Map.of("iat", now - 630, "exp", now - 30)), NONCE);
    }

    @Test
    void validateIdTokenUsesAKeyThatRanteLoginAddsLater() throws Exception {
        LocalIdp.SigningKey added = idp.addSigningKey("test-key-2");
        String token = idp.mintIdToken(Map.of("aud", WEB_CLIENT, "nonce", NONCE), added.privateKey(), "test-key-2");
        assertEquals("pairwise-subject-1", webClient(null).validateIdToken(token, NONCE).subject());
    }

    @Test
    void fetchUserInfoReturnsTheClaimsAndChecksTheSub() {
        RanteLoginClient client = webClient(null);
        AuthorizationRequest request = client.createAuthorizationRequest();
        RanteLoginResult result = client.handleCallback(callback(authorize(request, WEB_CLIENT), request.state(), idp.issuer), request.toExpected());
        UserInfo userinfo = client.fetchUserInfo(result.accessToken(), result.subject());
        assertEquals("pairwise-subject-1", userinfo.subject());
        assertEquals("Test Person", userinfo.claims().get("name"));
        List<LocalIdp.Recorded> calls = idp.requests.stream().filter(r -> r.path().endsWith("/userinfo")).toList();
        assertEquals("Bearer " + result.accessToken(), calls.get(calls.size() - 1).authorization());
        fails("userinfo_subject_mismatch", () -> client.fetchUserInfo(result.accessToken(), "someone-else"));
        assertEquals(401, fails("invalid_token", () -> client.fetchUserInfo("expired-or-unknown", null)).status());
    }

    @Test
    void fromBrowserSdkCookiesReadsTheThreeCookies() {
        String verifier = "v".repeat(43);
        ExpectedTransaction expected = new ExpectedTransaction("s1", "n1", verifier);
        assertEquals(expected, RanteLoginClient.fromBrowserSdkCookies(Map.of(BrowserSdkCookies.STATE, "s1", BrowserSdkCookies.NONCE, "n1",
                BrowserSdkCookies.CODE_VERIFIER, verifier)));
        assertEquals(expected, RanteLoginClient.fromBrowserSdkCookies("other=1; rante_login_pkce=" + verifier + "; rante_login_state=s1; rante_login_nonce=n1"));
        assertNull(RanteLoginClient.fromBrowserSdkCookies(Map.of(BrowserSdkCookies.STATE, "s1")));
        assertNull(RanteLoginClient.fromBrowserSdkCookies((String) null));
    }

    @Test
    void configurationRefusesBadSettings() throws Exception {
        KeyPairGenerator weak = KeyPairGenerator.getInstance("RSA");
        weak.initialize(1024);
        KeyPairGenerator p384 = KeyPairGenerator.getInstance("EC");
        p384.initialize(new ECGenParameterSpec("secp384r1"));
        PrivateKey weakKey = weak.generateKeyPair().getPrivate();
        PrivateKey p384Key = p384.generateKeyPair().getPrivate();
        PublicKey publicKey = rsa.getPublic();
        String publicPem = "-----BEGIN PUBLIC KEY-----\n" + Base64.getMimeEncoder().encodeToString(publicKey.getEncoded()) + "\n-----END PUBLIC KEY-----\n";
        Map<String, Runnable> bad = new LinkedHashMap<>();
        bad.put("client ID", () -> RanteLoginClient.builder().clientId("my-app").redirectUri(REDIRECT_URI).build());
        bad.put("http redirect URI", () -> RanteLoginClient.builder().clientId(WEB_CLIENT).redirectUri("http://shop.example.com/callback").build());
        bad.put("redirect URI with a fragment", () -> RanteLoginClient.builder().clientId(WEB_CLIENT).redirectUri("https://shop.example.com/callback#x").build());
        bad.put("scope without openid", () -> RanteLoginClient.builder().clientId(WEB_CLIENT).redirectUri(REDIRECT_URI).scope("profile email").build());
        bad.put("unknown scope", () -> RanteLoginClient.builder().clientId(WEB_CLIENT).redirectUri(REDIRECT_URI).scope("openid offline_access").build());
        bad.put("http issuer", () -> RanteLoginClient.builder().clientId(WEB_CLIENT).redirectUri(REDIRECT_URI).issuer("http://login.example.com/common/v2.0").build());
        bad.put("key prefix", () -> RanteLoginSigningKey.fromPrivateKey("my-key", rsa.getPrivate()));
        bad.put("RSA 1024", () -> RanteLoginSigningKey.fromPrivateKey(RSA_PREFIX, weakKey));
        bad.put("EC P-384", () -> RanteLoginSigningKey.fromPrivateKey(RSA_PREFIX, p384Key));
        bad.put("a public key", () -> RanteLoginSigningKey.fromPem(RSA_PREFIX, publicPem));
        for (Map.Entry<String, Runnable> entry : bad.entrySet()) {
            RanteLoginException error = assertThrows(RanteLoginException.class, entry.getValue()::run, entry.getKey());
            assertEquals("invalid_configuration", error.code(), entry.getKey());
        }
    }

    @Test
    void configurationReadsPemKeysAndNormalizesLikeTheBrowserSdk() {
        String rsaPem = "-----BEGIN PRIVATE KEY-----\n" + Base64.getMimeEncoder().encodeToString(rsa.getPrivate().getEncoded()) + "\n-----END PRIVATE KEY-----\n";
        String ecPem = "-----BEGIN PRIVATE KEY-----\n" + Base64.getMimeEncoder().encodeToString(ec.getPrivate().getEncoded()) + "\n-----END PRIVATE KEY-----\n";
        assertEquals("RS256", RanteLoginSigningKey.fromPem(RSA_PREFIX, rsaPem).algorithm());
        assertEquals("ES256", RanteLoginSigningKey.fromPem(EC_PREFIX, ecPem).algorithm());
        RanteLoginClient client = RanteLoginClient.builder().clientId(WEB_CLIENT.toUpperCase()).redirectUri("HTTPS://Shop.Example.com/Auth/Callback").build();
        assertEquals(WEB_CLIENT, client.clientId());
        assertEquals("https://shop.example.com/Auth/Callback", client.redirectUri());
        assertEquals("https://login.rante.com/common/v2.0", client.issuer());
    }

    @Test
    void discoveryThatNamesAnotherIssuerIsRefused() {
        idp.discoveryIssuer = "https://login.example.com/common/v2.0";
        try {
            fails("discovery_failed", () -> webClient(null).createAuthorizationRequest());
        } finally {
            idp.discoveryIssuer = idp.issuer;
        }
    }

    @Test
    void anUnreachableProviderIsANetworkError() {
        RanteLoginClient client = RanteLoginClient.builder().clientId(WEB_CLIENT).redirectUri(REDIRECT_URI)
                .issuer("http://127.0.0.1:9/common/v2.0").timeout(java.time.Duration.ofSeconds(2)).build();
        fails("network_error", client::createAuthorizationRequest);
    }

    private interface ThrowingSupplier<T> {
        T get() throws Exception;
    }

    private static <T> T unchecked(ThrowingSupplier<T> supplier) {
        try {
            return supplier.get();
        } catch (Exception error) {
            throw new IllegalStateException(error);
        }
    }
}
