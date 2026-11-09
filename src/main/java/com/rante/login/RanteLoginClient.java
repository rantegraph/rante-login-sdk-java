package com.rante.login;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * "Sign in with Rante" on a Java server, built on the Nimbus OAuth 2.0 / OpenID Connect SDK.
 *
 * <p>Rante Login is an OpenID Connect provider (issuer https://login.rante.com/common/v2.0) with the authorization
 * code flow with PKCE (S256), state, nonce and the {@code iss} response parameter (RFC 9207); client authentication by
 * {@code private_key_jwt} (RFC 7523) for server-side websites, or PKCE alone for browser-only websites; RS256 ID tokens
 * with a pairwise {@code sub}; and a userinfo endpoint. Create one client per app and keep it: it caches the discovery
 * document and the signing keys. It is safe to share between threads.
 */
public final class RanteLoginClient {
    /** https://login.rante.com/common/v2.0 */
    public static final String DEFAULT_ISSUER = "https://login.rante.com/common/v2.0";

    private static final long ASSERTION_LIFETIME_MILLIS = 60_000; // Rante Login accepts at most 5 minutes.
    private static final List<String> SCOPES = List.of("openid", "profile", "email", "phone", "address", "rante.organization");
    private static final List<String> PROMPTS = List.of("none", "login", "consent", "select_account");
    private static final Pattern GUID = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    private static final Pattern ERROR_CODE = Pattern.compile("^[a-z0-9_]{1,64}$");
    private static final Pattern NONCE = Pattern.compile("^[\\x21-\\x7e]{1,256}$");
    private static final Pattern SCHEME_AND_HOST = Pattern.compile("^[A-Za-z][A-Za-z0-9+.-]*://[^/?#]*");

    private final String clientId;
    private final String redirectUri;
    private final String scope;
    private final String issuer;
    private final RanteLoginSigningKey signingKey;
    private final int timeoutMillis;
    private final int clockSkewSeconds;
    private volatile Provider provider;

    private RanteLoginClient(Builder builder) {
        this.clientId = normalizeClientId(builder.clientId);
        this.redirectUri = normalizeRedirectUri(builder.redirectUri);
        this.scope = normalizeScope(builder.scope);
        this.issuer = normalizeIssuer(builder.issuer);
        this.signingKey = builder.signingKey;
        this.timeoutMillis = (int) builder.timeout.toMillis();
        this.clockSkewSeconds = (int) builder.clockSkew.toSeconds();
    }

    /** A builder for one app's client. */
    public static Builder builder() {
        return new Builder();
    }

    /** The app's Application (client) ID, in lower case. */
    public String clientId() {
        return clientId;
    }

    /** The redirect URI, with its scheme and host in lower case like the browser SDK sends it. */
    public String redirectUri() {
        return redirectUri;
    }

    /** The scopes requested. */
    public String scope() {
        return scope;
    }

    /** The issuer. */
    public String issuer() {
        return issuer;
    }

    /** {@code private_key_jwt} with the app's Signed JWT key, or {@code none} (PKCE alone). */
    public String clientAuthentication() {
        return signingKey == null ? "none" : "private_key_jwt";
    }

    /** Starts a sign-in on the server; see {@link #createAuthorizationRequest(AuthorizationRequestOptions)}. */
    public AuthorizationRequest createAuthorizationRequest() {
        return createAuthorizationRequest(AuthorizationRequestOptions.none());
    }

    /**
     * Starts a sign-in on the server: the URL to send the browser to, and the values to keep (in the server-side
     * session) until the browser comes back to the redirect URI.
     */
    public AuthorizationRequest createAuthorizationRequest(AuthorizationRequestOptions options) {
        AuthorizationRequestOptions o = options == null ? AuthorizationRequestOptions.none() : options;
        Nonce nonce = o.nonce() == null ? new Nonce() : new Nonce(checkNonce(o.nonce()));
        String prompt = checkPrompt(o.prompt());
        if (o.loginHint() != null && o.loginHint().length() > 256) {
            throw new RanteLoginException("invalid_request", "loginHint must be at most 256 characters.");
        }
        if (o.maxAge() != null && o.maxAge() < 0) {
            throw new RanteLoginException("invalid_request", "maxAge must be a whole number of seconds.");
        }
        Provider p = provider();
        State state = new State();
        CodeVerifier codeVerifier = new CodeVerifier();
        AuthenticationRequest.Builder request = new AuthenticationRequest.Builder(
                new ResponseType(ResponseType.Value.CODE), Scope.parse(scope), new ClientID(clientId), URI.create(redirectUri))
                .endpointURI(p.authorizationEndpoint)
                .state(state)
                .nonce(nonce)
                .codeChallenge(codeVerifier, CodeChallengeMethod.S256);
        if (prompt != null) {
            try {
                request.prompt(Prompt.parse(prompt));
            } catch (ParseException error) {
                throw new RanteLoginException("invalid_request", error.getMessage());
            }
        }
        if (o.loginHint() != null && !o.loginHint().isEmpty()) {
            request.loginHint(o.loginHint());
        }
        if (o.maxAge() != null) {
            request.maxAge(o.maxAge());
        }
        return new AuthorizationRequest(request.build().toURI().toString(), state.getValue(), nonce.getValue(), codeVerifier.getValue());
    }

    /**
     * Finishes a redirect sign-in at the redirect URI: checks the response against the values kept for it, exchanges
     * the code and validates the ID token.
     *
     * @param callbackUri the redirect URI as requested, with its query
     * @param expected what {@link #createAuthorizationRequest()} returned ({@link AuthorizationRequest#toExpected()}),
     *     or {@link #fromBrowserSdkCookies(Map)} when the browser SDK started the sign-in
     */
    public RanteLoginResult handleCallback(URI callbackUri, ExpectedTransaction expected) {
        return handleCallback(callbackUri.getRawQuery() == null ? "" : callbackUri.getRawQuery(), expected);
    }

    /** The same, from the redirect's raw query string (for example {@code exchange.getRequestURI().getRawQuery()}). */
    public RanteLoginResult handleCallback(String rawQuery, ExpectedTransaction expected) {
        Map<String, List<String>> query = new LinkedHashMap<>();
        String text = rawQuery == null ? "" : rawQuery.startsWith("?") ? rawQuery.substring(1) : rawQuery;
        for (String pair : text.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int index = pair.indexOf('=');
            String name = URLDecoder.decode(index < 0 ? pair : pair.substring(0, index), StandardCharsets.UTF_8);
            String value = index < 0 ? "" : URLDecoder.decode(pair.substring(index + 1), StandardCharsets.UTF_8);
            query.computeIfAbsent(name, key -> new ArrayList<>()).add(value);
        }
        return handleCallback(query, expected);
    }

    /** The same, from the parsed query (for example a servlet's {@code request.getParameterMap()}, as lists). */
    public RanteLoginResult handleCallback(Map<String, List<String>> query, ExpectedTransaction expected) {
        Map<String, String> response = new LinkedHashMap<>();
        for (String name : List.of("code", "state", "iss", "error", "error_description")) {
            List<String> values = query == null ? null : query.get(name);
            if (values != null && values.size() > 1) {
                throw new RanteLoginException("invalid_request", "The response repeats " + name + ".");
            }
            response.put(name, values == null || values.isEmpty() ? null : values.get(0));
        }
        if (expected == null || isEmpty(expected.state()) || isEmpty(expected.nonce()) || isEmpty(expected.codeVerifier())) {
            throw new RanteLoginException("missing_transaction", "No sign-in is in progress for this browser, or it expired.");
        }
        if (!safeEquals(response.get("state"), expected.state())) {
            throw new RanteLoginException("state_mismatch", "The response does not belong to the sign-in this browser started.");
        }
        if (!issuer.equals(response.get("iss"))) { // RFC 9207
            throw new RanteLoginException("issuer_mismatch", "The response did not come from Rante Login.");
        }
        String error = response.get("error");
        if (!isEmpty(error)) {
            String description = clean(response.get("error_description"));
            throw new RanteLoginException(ERROR_CODE.matcher(error).matches() ? error : "authorization_failed",
                    description.isEmpty() ? error : description);
        }
        String code = response.get("code");
        if (isEmpty(code)) {
            throw new RanteLoginException("invalid_request", "The response has no code.");
        }
        TokenSet tokens = exchangeCode(code, expected.codeVerifier());
        return new RanteLoginResult(validateIdToken(tokens.idToken(), expected.nonce()), tokens);
    }

    /** The token request: the code, the PKCE verifier and the app's client authentication. */
    public TokenSet exchangeCode(String code, String codeVerifier) {
        if (isEmpty(code) || isEmpty(codeVerifier)) {
            throw new RanteLoginException("invalid_request", "The code and the code verifier are required.");
        }
        Provider p = provider();
        AuthorizationCodeGrant grant;
        try {
            grant = new AuthorizationCodeGrant(new AuthorizationCode(code), URI.create(redirectUri), new CodeVerifier(codeVerifier));
        } catch (IllegalArgumentException error) {
            throw new RanteLoginException("invalid_request", "The code verifier is malformed.");
        }
        // A browser-only app sends no credential at all: the PKCE verifier is its only proof. A server-side website
        // sends its client assertion, and client_id too: Rante Login needs it in the form even with private_key_jwt
        // (RFC 7523 makes it optional, so the Nimbus SDK leaves it out unless asked).
        TokenRequest request = signingKey == null
                ? new TokenRequest.Builder(p.tokenEndpoint, new ClientID(clientId), grant).build()
                : new TokenRequest.Builder(p.tokenEndpoint, clientAssertion(p.tokenEndpoint), grant).customParameter("client_id", clientId).build();
        HTTPResponse response = send(request.toHTTPRequest());
        TokenResponse parsed;
        try {
            parsed = OIDCTokenResponseParser.parse(response);
        } catch (ParseException error) {
            throw new RanteLoginException("token_request_failed", "The token endpoint answered " + response.getStatusCode() + ".",
                    response.getStatusCode(), error);
        }
        if (!parsed.indicatesSuccess()) {
            ErrorObject failure = parsed.toErrorResponse().getErrorObject();
            String errorCode = failure.getCode();
            String description = clean(failure.getDescription());
            throw new RanteLoginException(errorCode != null && ERROR_CODE.matcher(errorCode).matches() ? errorCode : "token_request_failed",
                    description.isEmpty() ? "The token endpoint answered " + response.getStatusCode() + "." : description,
                    response.getStatusCode(), null);
        }
        if (!(parsed instanceof OIDCTokenResponse oidc) || oidc.getOIDCTokens().getIDTokenString() == null) {
            throw new RanteLoginException("invalid_token_response", "The token response has no ID token.");
        }
        AccessToken accessToken = oidc.getOIDCTokens().getAccessToken();
        if (!(accessToken instanceof BearerAccessToken)) {
            throw new RanteLoginException("invalid_token_response", "The token response has no Bearer access token.");
        }
        long lifetime = accessToken.getLifetime();
        return new TokenSet(accessToken.getValue(), "Bearer", lifetime > 0 ? lifetime : null,
                oidc.getOIDCTokens().getIDTokenString(), accessToken.getScope() == null ? null : accessToken.getScope().toString());
    }

    /**
     * Validates an ID token before you trust it: the RS256 signature with the key its {@code kid} names in Rante
     * Login's JWKS, {@code iss}, {@code aud} (and {@code azp}), {@code exp} (with clock skew), {@code iat},
     * {@code sub}, and the nonce you expect.
     */
    public ValidatedIdToken validateIdToken(String idToken, String nonce) {
        if (isEmpty(nonce)) {
            throw new RanteLoginException("invalid_request", "The expected nonce is required.");
        }
        if (isEmpty(idToken)) {
            throw new RanteLoginException("invalid_id_token", "The ID token is missing.");
        }
        Provider p = provider();
        JWT jwt;
        IDTokenClaimsSet claims;
        try {
            jwt = JWTParser.parse(idToken);
            claims = p.validator.validate(jwt, new Nonce(nonce));
        } catch (KeySourceException error) {
            throw new RanteLoginException("network_error", "Rante Login's signing keys could not be fetched.", null, error);
        } catch (java.text.ParseException | BadJOSEException | JOSEException error) {
            throw new RanteLoginException("invalid_id_token",
                    "The ID token failed validation (" + error.getClass().getSimpleName() + ": " + clean(error.getMessage()) + ").", null, error);
        }
        if (claims.getAuthorizedParty() != null && !clientId.equals(claims.getAuthorizedParty().getValue())) {
            throw new RanteLoginException("invalid_id_token", "The ID token was issued to another app (azp).");
        }
        try {
            // The claims as the token's JSON has them: a single audience is a string, times are seconds since the epoch.
            return new ValidatedIdToken(claims.getSubject().getValue(), jwt.getJWTClaimsSet().toJSONObject());
        } catch (java.text.ParseException error) {
            throw new RanteLoginException("invalid_id_token", "The ID token's claims could not be read.", null, error);
        }
    }

    /**
     * The person's claims from the userinfo endpoint, with the access token from the code exchange (15 minutes).
     * Pass the ID token's {@code sub} as {@code expectedSubject}: OpenID Connect requires that both match.
     */
    public UserInfo fetchUserInfo(String accessToken, String expectedSubject) {
        if (isEmpty(accessToken)) {
            throw new RanteLoginException("invalid_request", "An access token is required.");
        }
        Provider p = provider();
        HTTPResponse response = send(new UserInfoRequest(p.userinfoEndpoint, new BearerAccessToken(accessToken)).toHTTPRequest());
        if (response.getStatusCode() == 401) {
            throw new RanteLoginException("invalid_token", "The access token was refused: it expired, or the person removed their consent.", 401, null);
        }
        UserInfoResponse parsed;
        try {
            parsed = UserInfoResponse.parse(response);
        } catch (ParseException error) {
            throw new RanteLoginException("userinfo_failed", "The userinfo endpoint answered " + response.getStatusCode() + ".", response.getStatusCode(), error);
        }
        if (!parsed.indicatesSuccess() || parsed.toSuccessResponse().getUserInfo() == null) {
            throw new RanteLoginException("userinfo_failed", "The userinfo endpoint answered " + response.getStatusCode() + ".", response.getStatusCode(), null);
        }
        com.nimbusds.openid.connect.sdk.claims.UserInfo info = parsed.toSuccessResponse().getUserInfo();
        String subject = info.getSubject().getValue();
        if (expectedSubject != null && !expectedSubject.equals(subject)) {
            throw new RanteLoginException("userinfo_subject_mismatch", "The userinfo sub is not the ID token's sub.");
        }
        return new UserInfo(subject, info.toJSONObject());
    }

    /**
     * The values the browser SDK ({@code serverSide: true}) kept for a redirect sign-in, from the request's cookies by
     * name. Null when any is missing. Clear the three cookies ({@link BrowserSdkCookies#ALL}) once read: each sign-in
     * uses them once.
     */
    public static ExpectedTransaction fromBrowserSdkCookies(Map<String, String> cookies) {
        if (cookies == null) {
            return null;
        }
        String state = cookies.get(BrowserSdkCookies.STATE);
        String nonce = cookies.get(BrowserSdkCookies.NONCE);
        String verifier = cookies.get(BrowserSdkCookies.CODE_VERIFIER);
        return isEmpty(state) || isEmpty(nonce) || isEmpty(verifier) ? null : new ExpectedTransaction(state, nonce, verifier);
    }

    /** The same, from the Cookie header. */
    public static ExpectedTransaction fromBrowserSdkCookies(String cookieHeader) {
        Map<String, String> cookies = new LinkedHashMap<>();
        for (String part : (cookieHeader == null ? "" : cookieHeader).split(";")) {
            int index = part.indexOf('=');
            if (index > 0) {
                cookies.putIfAbsent(part.substring(0, index).trim(), part.substring(index + 1).trim());
            }
        }
        return fromBrowserSdkCookies(cookies);
    }

    // ------------------------------------------------------------------------------------------------ internals

    // The discovery document (fetched once; a failed fetch is tried again next time), and an ID token validator whose
    // JWKS source caches the keys and fetches them again when a token names a kid it doesn't know (key rotation).
    private Provider provider() {
        Provider current = provider;
        if (current != null) {
            return current;
        }
        synchronized (this) {
            if (provider == null) {
                OIDCProviderMetadata metadata;
                try {
                    metadata = OIDCProviderMetadata.resolve(new Issuer(issuer), timeoutMillis, timeoutMillis);
                } catch (IOException error) {
                    throw new RanteLoginException("network_error", "Rante Login could not be reached (" + error.getClass().getSimpleName() + ").", null, error);
                } catch (GeneralException error) {
                    throw new RanteLoginException("discovery_failed", "The discovery document could not be used: " + clean(error.getMessage()), null, error);
                }
                if (!issuer.equals(metadata.getIssuer().getValue()) || metadata.getAuthorizationEndpointURI() == null
                        || metadata.getTokenEndpointURI() == null || metadata.getUserInfoEndpointURI() == null || metadata.getJWKSetURI() == null) {
                    throw new RanteLoginException("discovery_failed", "The discovery document names another issuer or lacks an endpoint.");
                }
                IDTokenValidator validator;
                try {
                    validator = new IDTokenValidator(new Issuer(issuer), new ClientID(clientId), JWSAlgorithm.RS256,
                            metadata.getJWKSetURI().toURL(), new DefaultResourceRetriever(timeoutMillis, timeoutMillis, 512 * 1024));
                } catch (java.net.MalformedURLException error) {
                    throw new RanteLoginException("discovery_failed", "The discovery document's jwks_uri is not a URL.", null, error);
                }
                validator.setMaxClockSkew(clockSkewSeconds);
                provider = new Provider(metadata.getAuthorizationEndpointURI(), metadata.getTokenEndpointURI(),
                        metadata.getUserInfoEndpointURI(), validator);
            }
            return provider;
        }
    }

    // private_key_jwt (RFC 7523): a short-lived JWT signed with the app's private key. iss and sub are the client ID,
    // aud the token endpoint, the kid the Signed JWT key's prefix, and the jti unique (Rante Login accepts it once).
    private PrivateKeyJWT clientAssertion(URI tokenEndpoint) {
        Date now = new Date();
        JWTAuthenticationClaimsSet claims = new JWTAuthenticationClaimsSet(new ClientID(clientId), List.of(new Audience(tokenEndpoint)),
                new Date(now.getTime() + ASSERTION_LIFETIME_MILLIS), now, now, new JWTID());
        try {
            return new PrivateKeyJWT(claims, signingKey.jwsAlgorithm(), signingKey.privateKey(), signingKey.keyPrefix(), null);
        } catch (JOSEException error) {
            throw new RanteLoginException("invalid_configuration", "The client assertion could not be signed.", null, error);
        }
    }

    private HTTPResponse send(HTTPRequest request) {
        request.setConnectTimeout(timeoutMillis);
        request.setReadTimeout(timeoutMillis);
        request.setFollowRedirects(false);
        request.setAccept("application/json");
        try {
            return request.send();
        } catch (IOException error) {
            throw new RanteLoginException("network_error", "Rante Login could not be reached (" + error.getClass().getSimpleName() + ").", null, error);
        }
    }

    private static String normalizeClientId(String value) {
        String id = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        if (!GUID.matcher(id).matches()) {
            throw invalid("clientId must be the app's Application (client) ID from the Rante Portal.");
        }
        return id;
    }

    // Rante Login matches redirect URIs exactly, and stores them with the scheme and host in lower case.
    private static String normalizeRedirectUri(String value) {
        String text = value == null ? "" : value.trim();
        java.util.regex.Matcher prefix = SCHEME_AND_HOST.matcher(text);
        String uri = prefix.find() ? prefix.group().toLowerCase(Locale.ROOT) + text.substring(prefix.end()) : text;
        try {
            URI parsed = new URI(uri);
            boolean loopback = "localhost".equals(parsed.getHost()) || "127.0.0.1".equals(parsed.getHost());
            if (parsed.isAbsolute() && parsed.getHost() != null && parsed.getRawFragment() == null && !uri.contains("#")
                    && parsed.getRawUserInfo() == null && uri.length() <= 512
                    && ("https".equals(parsed.getScheme()) || ("http".equals(parsed.getScheme()) && loopback))) {
                return uri;
            }
        } catch (URISyntaxException ignored) {
            // Refused below.
        }
        throw invalid("redirectUri must be the absolute https URI registered on the app (http only for localhost or 127.0.0.1), without a fragment.");
    }

    private static String normalizeScope(String value) {
        List<String> parts = Arrays.stream((value == null ? "" : value).trim().split("\\s+")).filter(part -> !part.isEmpty()).toList();
        if (!parts.contains("openid") || !SCOPES.containsAll(parts)) {
            throw invalid("scope must include openid and only these scopes: " + String.join(", ", SCOPES) + ".");
        }
        return String.join(" ", new LinkedHashSet<>(parts));
    }

    private static String normalizeIssuer(String value) {
        try {
            URI parsed = new URI(value);
            boolean loopback = "localhost".equals(parsed.getHost()) || "127.0.0.1".equals(parsed.getHost());
            if (parsed.getRawQuery() == null && parsed.getRawFragment() == null
                    && ("https".equals(parsed.getScheme()) || ("http".equals(parsed.getScheme()) && loopback))) {
                return value.replaceAll("/+$", "");
            }
        } catch (URISyntaxException | NullPointerException ignored) {
            // Refused below.
        }
        throw invalid("issuer must be an https URL.");
    }

    private static String checkNonce(String nonce) {
        if (!NONCE.matcher(nonce).matches()) {
            throw new RanteLoginException("invalid_request", "nonce must be 1 to 256 printable ASCII characters without spaces.");
        }
        return nonce;
    }

    private static String checkPrompt(String prompt) {
        if (prompt == null || prompt.isEmpty()) {
            return null;
        }
        List<String> parts = Arrays.stream(prompt.trim().split("\\s+")).filter(part -> !part.isEmpty()).toList();
        if (parts.isEmpty() || !PROMPTS.containsAll(parts) || (parts.contains("none") && parts.size() > 1)) {
            throw new RanteLoginException("invalid_request", "prompt must be " + String.join(", ", PROMPTS) + " (none alone).");
        }
        return String.join(" ", parts);
    }

    private static boolean safeEquals(String a, String b) {
        return a != null && b != null && MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private static String clean(String value) {
        if (value == null) {
            return "";
        }
        String cleaned = value.replaceAll("[\\x00-\\x1f\\x7f]", " ");
        return cleaned.length() > 300 ? cleaned.substring(0, 300) : cleaned;
    }

    private static boolean isEmpty(String value) {
        return value == null || value.isEmpty();
    }

    private static RanteLoginException invalid(String message) {
        return new RanteLoginException("invalid_configuration", message);
    }

    private record Provider(URI authorizationEndpoint, URI tokenEndpoint, URI userinfoEndpoint, IDTokenValidator validator) {
    }

    /** Settings for one app's client. */
    public static final class Builder {
        private String clientId;
        private String redirectUri;
        private String scope = "openid profile email";
        private RanteLoginSigningKey signingKey;
        private String issuer = DEFAULT_ISSUER;
        private Duration timeout = Duration.ofSeconds(10);
        private Duration clockSkew = Duration.ofSeconds(60);

        private Builder() {
        }

        /** The app's Application (client) ID. */
        public Builder clientId(String value) {
            clientId = value;
            return this;
        }

        /** Exactly as registered on the app. */
        public Builder redirectUri(String value) {
            redirectUri = value;
            return this;
        }

        /** Default {@code openid profile email}. Request only scopes whose information the app asks for. */
        public Builder scope(String value) {
            scope = value;
            return this;
        }

        /** Server-side websites: the Signed JWT key linked to the app. Without it, PKCE alone (browser-only websites). */
        public Builder signingKey(RanteLoginSigningKey value) {
            signingKey = value;
            return this;
        }

        /** Default https://login.rante.com/common/v2.0. */
        public Builder issuer(String value) {
            issuer = value;
            return this;
        }

        /** The time each request to Rante Login may take. Default 10 seconds. */
        public Builder timeout(Duration value) {
            timeout = value;
            return this;
        }

        /** The clock skew allowed for the ID token. Default 60 seconds. */
        public Builder clockSkew(Duration value) {
            clockSkew = value;
            return this;
        }

        /** @throws RanteLoginException with code {@code invalid_configuration} when a setting is wrong */
        public RanteLoginClient build() {
            return new RanteLoginClient(this);
        }
    }
}
