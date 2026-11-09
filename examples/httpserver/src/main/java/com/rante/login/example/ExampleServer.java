package com.rante.login.example;

import com.nimbusds.jose.util.JSONArrayUtils;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.rante.login.AuthorizationRequest;
import com.rante.login.BrowserSdkCookies;
import com.rante.login.ExpectedTransaction;
import com.rante.login.RanteLoginClient;
import com.rante.login.RanteLoginException;
import com.rante.login.RanteLoginResult;
import com.rante.login.RanteLoginSigningKey;
import com.rante.login.UserInfo;
import com.rante.login.ValidatedIdToken;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.logging.Logger;

/**
 * Sign in with Rante: a website on the JDK's built-in HTTP server that signs people in with the Rante Login SDK for
 * Java.
 *
 * <p>Three ways in, all finished and checked on this server:
 * <ul>
 *   <li>"Sign in with Rante" button (signin.js): the browser SDK with {@code serverSide: true}. In Chrome and Edge it
 *   uses FedCM and posts the ID token to /auth/rante/fedcm; elsewhere it redirects, and the code comes back to the
 *   redirect URI with the SDK's rante_login_* cookies.</li>
 *   <li>"Sign in without JavaScript" link: /auth/rante/sign-in builds the authorize request here
 *   ({@code createAuthorizationRequest}) and keeps its state, nonce and PKCE verifier in the session.</li>
 *   <li>Either redirect ends at the redirect URI, where {@code handleCallback} exchanges the code (private_key_jwt or
 *   PKCE alone) and validates the ID token.</li>
 * </ul>
 */
public final class ExampleServer {
    private static final Logger LOG = Logger.getLogger("rante-login-example");
    private static final String SDK_SRC = "https://login.rante.com/sdk/v1/rante-login.js";
    private static final String SDK_INTEGRITY = "sha384-2W12/NktCjRqFuXWiUtHr1yEtdrjBlCRWnJ+//FZMiqd1KRX/K+YMWLoMgF9R7wf";
    private static final String SESSION_COOKIE = "rante_httpserver_session";
    private static final String CSP = String.join("; ",
            "default-src 'self'",
            "script-src 'self' https://login.rante.com", // the browser SDK, pinned by its integrity hash
            "connect-src 'self' https://login.rante.com", // FedCM fetches the identity provider's configuration
            "img-src 'self' data:",
            "style-src 'self'",
            "base-uri 'none'",
            "form-action 'self'",
            "frame-ancestors 'none'");
    private static final SecureRandom RANDOM = new SecureRandom();

    /** One browser's server-side session. */
    private static final class Session {
        volatile String nonce;
        volatile ExpectedTransaction started;
        volatile Map<String, Object> claims;
        volatile String accessToken;
        volatile String method;
        volatile Instant signedInAt;
        volatile boolean newAccount;
        volatile Instant lastSeen = Instant.now();
    }

    /** One account on this website, created by the person's first "Sign in with Rante" here and found by {@code sub} after that. */
    private record Account(String id, String sub, String name, String email, Instant createdAt, Instant lastSignInAt) {
    }

    // This website's own accounts. A person's first "Sign in with Rante" here is their sign-up: the account is created from
    // the claims they agreed to share, and every later sign-in finds it by `sub`. A real website keeps accounts in its
    // database; this example keeps them in memory, so they're gone when the server restarts.
    private final Map<String, Account> accounts = new ConcurrentHashMap<>();

    private final RanteLoginClient rante;
    private final String siteOrigin;
    private final String callbackPath;
    private final boolean secureCookies;
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    private ExampleServer(RanteLoginClient rante) {
        this.rante = rante;
        URI redirect = URI.create(rante.redirectUri());
        this.siteOrigin = redirect.getScheme() + "://" + redirect.getRawAuthority();
        this.callbackPath = redirect.getRawPath();
        this.secureCookies = "https".equals(redirect.getScheme());
    }

    public static void main(String[] args) throws IOException {
        Map<String, String> env = System.getenv();
        String keyPrefix = env.getOrDefault("RANTE_LOGIN_KEY_PREFIX", "");
        String keyFile = env.getOrDefault("RANTE_LOGIN_PRIVATE_KEY_FILE", "");
        RanteLoginClient rante;
        try {
            if (keyPrefix.isEmpty() != keyFile.isEmpty()) {
                throw new RanteLoginException("invalid_configuration",
                        "Set both RANTE_LOGIN_KEY_PREFIX and RANTE_LOGIN_PRIVATE_KEY_FILE (a server-side website), or neither (browser-only).");
            }
            RanteLoginClient.Builder builder = RanteLoginClient.builder()
                    .clientId(env.getOrDefault("RANTE_LOGIN_CLIENT_ID", ""))
                    .redirectUri(env.getOrDefault("RANTE_LOGIN_REDIRECT_URI", "http://localhost:3000/auth/rante/callback"))
                    .scope(env.getOrDefault("RANTE_LOGIN_SCOPE", "openid profile email"));
            if (!keyFile.isEmpty()) {
                builder.signingKey(RanteLoginSigningKey.fromPem(keyPrefix, Files.readString(Path.of(keyFile))));
            }
            rante = builder.build();
        } catch (RanteLoginException | IOException error) {
            System.err.println(error.getMessage());
            System.exit(1);
            return;
        }
        ExampleServer example = new ExampleServer(rante);
        if (java.util.List.of("/", "/auth/rante/sign-in", "/auth/rante/fedcm", "/auth/sign-out", "/userinfo", "/signin.js", "/style.css")
                .contains(example.callbackPath)) {
            System.err.println("Give RANTE_LOGIN_REDIRECT_URI a path of its own, for example /auth/rante/callback.");
            System.exit(1);
        }
        URI redirect = URI.create(rante.redirectUri());
        int port = env.containsKey("PORT") ? Integer.parseInt(env.get("PORT")) : redirect.getPort() > 0 ? redirect.getPort() : 3000;
        HttpServer server = HttpServer.create(new InetSocketAddress(env.getOrDefault("HOST", "127.0.0.1"), port), 0);
        server.createContext("/", example::handle);
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println("Sign in with Rante (JDK HTTP server example): " + example.siteOrigin + "/ - client " + rante.clientId() + ", "
                + rante.clientAuthentication());
    }

    private void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            exchange.getResponseHeaders().set("Content-Security-Policy", CSP);
            exchange.getResponseHeaders().set("Referrer-Policy", "same-origin");
            exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
            String method = exchange.getRequestMethod();
            String path = exchange.getRequestURI().getRawPath();
            boolean read = method.equals("GET") || method.equals("HEAD"); // HEAD: the same headers, no body (see send)
            if (read && path.equals("/")) {
                home(exchange);
            } else if (read && (path.equals("/signin.js") || path.equals("/style.css"))) {
                asset(exchange, path.substring(1));
            } else if (method.equals("GET") && path.equals("/auth/rante/sign-in")) {
                signIn(exchange);
            } else if (method.equals("GET") && path.equals(callbackPath)) {
                callback(exchange);
            } else if (method.equals("POST") && path.equals("/auth/rante/fedcm")) {
                fedcm(exchange);
            } else if (method.equals("GET") && path.equals("/userinfo")) {
                userinfo(exchange);
            } else if (method.equals("POST") && path.equals("/auth/sign-out")) {
                signOut(exchange);
            } else {
                html(exchange, 404, page("Not found", "<h1>Not found</h1><p><a href=\"/\">Home</a></p>"));
            }
        } catch (RuntimeException error) {
            LOG.severe("Request failed: " + error);
            html(exchange, 500, page("Error", "<h1>Something went wrong</h1><p>The server's log has the details.</p>"));
        }
    }

    private void home(HttpExchange exchange) throws IOException {
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        Session session = session(exchange, true);
        if (session.claims != null) {
            html(exchange, 200, signedInPage(session));
            return;
        }
        // FedCM hands the ID token to the page, so its nonce must be one the page can't choose: issue it here and keep
        // it in the session. The browser SDK sends the same nonce in its redirect flow.
        if (session.nonce == null) {
            session.nonce = randomToken();
        }
        html(exchange, 200, signInPage(session.nonce));
    }

    // The server starts the sign-in: no JavaScript needed.
    private void signIn(HttpExchange exchange) throws IOException {
        Session session = session(exchange, true);
        try {
            AuthorizationRequest request = rante.createAuthorizationRequest();
            session.started = request.toExpected();
            redirect(exchange, request.url());
        } catch (RanteLoginException error) {
            error(exchange, error);
        }
    }

    // The redirect URI: Rante Login comes back with ?code=...&state=...&iss=... (or ?error=...).
    private void callback(HttpExchange exchange) throws IOException {
        // A sign-in this server started is in the session; one the browser SDK started is in its cookies. Both are used once.
        Session session = session(exchange, true);
        ExpectedTransaction started = session.started;
        session.started = null;
        ExpectedTransaction fromBrowser = RanteLoginClient.fromBrowserSdkCookies(exchange.getRequestHeaders().getFirst("Cookie"));
        for (String name : BrowserSdkCookies.ALL) {
            exchange.getResponseHeaders().add("Set-Cookie", name + "=; Path=/; Max-Age=0; SameSite=Lax" + (secureCookies ? "; Secure" : ""));
        }
        String rawQuery = exchange.getRequestURI().getRawQuery();
        String state = queryValue(rawQuery, "state");
        boolean byServer = started != null && started.state().equals(state);
        try {
            RanteLoginResult result = rante.handleCallback(rawQuery, byServer ? started : fromBrowser != null ? fromBrowser : started);
            startSession(exchange, result.idToken(), result.accessToken(),
                    (byServer ? "Redirect started by the server" : "Redirect started by the browser SDK") + ", " + rante.clientAuthentication());
            redirect(exchange, "/");
        } catch (RanteLoginException error) {
            error(exchange, error);
        }
    }

    // FedCM: the page posts the ID token the browser's account dialog returned.
    private void fedcm(HttpExchange exchange) throws IOException {
        if (!siteOrigin.equals(exchange.getRequestHeaders().getFirst("Origin"))) {
            json(exchange, 403, "{\"error\":\"origin_not_allowed\"}");
            return;
        }
        Session session = session(exchange, false);
        try {
            if (session == null || session.nonce == null) {
                throw new RanteLoginException("missing_transaction", "This browser session has no sign-in nonce. Reload the page.");
            }
            String idToken = null;
            byte[] body = readAtMost(exchange.getRequestBody(), 16 * 1024);
            if (body != null && String.valueOf(exchange.getRequestHeaders().getFirst("Content-Type")).startsWith("application/json")) {
                try {
                    Object value = JSONObjectUtils.parse(new String(body, StandardCharsets.UTF_8)).get("idToken");
                    idToken = value instanceof String text ? text : null;
                } catch (java.text.ParseException ignored) {
                    // Not JSON: no ID token.
                }
            }
            ValidatedIdToken token = rante.validateIdToken(idToken, session.nonce);
            startSession(exchange, token, null, "FedCM");
            exchange.sendResponseHeaders(204, -1);
        } catch (RanteLoginException error) {
            LOG.warning("FedCM sign-in failed: " + error.code() + ": " + error.getMessage());
            json(exchange, 400, "{\"error\":\"" + error.code() + "\"}");
        }
    }

    // The person's claims from Rante Login's userinfo endpoint, with the access token from the code exchange (15 minutes).
    private void userinfo(HttpExchange exchange) throws IOException {
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        Session session = session(exchange, false);
        if (session == null || session.claims == null) {
            redirect(exchange, "/");
            return;
        }
        if (session.accessToken == null) {
            html(exchange, 200, page("Userinfo", "<h1>Userinfo</h1><p>FedCM sign-ins return only an ID token, so there is no access token to call "
                    + "userinfo with.</p><p><a href=\"/\">Back</a></p>"));
            return;
        }
        try {
            UserInfo info = rante.fetchUserInfo(session.accessToken, (String) session.claims.get("sub"));
            html(exchange, 200, page("Userinfo", "<h1>Userinfo</h1><p>From GET https://login.rante.com/common/oidc/v2.0/userinfo:</p>"
                    + table(info.claims()) + "<p><a href=\"/\">Back</a></p>"));
        } catch (RanteLoginException error) {
            error(exchange, error);
        }
    }

    private void signOut(HttpExchange exchange) throws IOException {
        String origin = exchange.getRequestHeaders().getFirst("Origin");
        if (origin != null && !origin.equals(siteOrigin)) {
            exchange.sendResponseHeaders(403, -1);
            return;
        }
        // Signs out of this website only; the person stays signed in to Rante.
        String id = cookie(exchange, SESSION_COOKIE);
        if (id != null) {
            sessions.remove(id);
        }
        exchange.getResponseHeaders().add("Set-Cookie", SESSION_COOKIE + "=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax" + (secureCookies ? "; Secure" : ""));
        redirect(exchange, "/");
    }

    // A new session for the person who signed in: its ID changes, so a session fixed before sign-in is worthless. The
    // sign-in also creates or finds their account on this website.
    private void startSession(HttpExchange exchange, ValidatedIdToken token, String accessToken, String method) {
        String old = cookie(exchange, SESSION_COOKIE);
        if (old != null) {
            sessions.remove(old);
        }
        Session session = new Session();
        session.claims = token.claims();
        session.accessToken = accessToken;
        session.method = method;
        session.signedInAt = Instant.now();
        session.newAccount = registerOrFind(token.claims());
        String id = randomToken();
        sessions.put(id, session);
        setSessionCookie(exchange, id);
    }

    /** Creates the person's account on the first sign-in, or finds it by {@code sub}; true when it was created now. */
    private boolean registerOrFind(Map<String, Object> claims) {
        String sub = String.valueOf(claims.get("sub"));
        String name = claims.get("name") instanceof String nameValue ? nameValue : null;
        String email = claims.get("email") instanceof String emailValue ? emailValue : null;
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        boolean[] created = {false};
        accounts.compute(sub, (key, existing) -> {
            if (existing == null) {
                created[0] = true;
                return new Account(UUID.randomUUID().toString(), sub, name, email, now, now);
            }
            // Keep the details the person shares this time. Rante shares an email only once it's verified.
            return new Account(existing.id(), sub, name != null ? name : existing.name(), email != null ? email : existing.email(),
                    existing.createdAt(), now);
        });
        return created[0];
    }

    private Session session(HttpExchange exchange, boolean create) {
        Instant cutoff = Instant.now().minusSeconds(8 * 60 * 60);
        sessions.values().removeIf(s -> s.lastSeen.isBefore(cutoff));
        String id = cookie(exchange, SESSION_COOKIE);
        Session session = id == null ? null : sessions.get(id);
        if (session == null && create) {
            session = new Session();
            id = randomToken();
            sessions.put(id, session);
            setSessionCookie(exchange, id);
        }
        if (session != null) {
            session.lastSeen = Instant.now();
        }
        return session;
    }

    private void setSessionCookie(HttpExchange exchange, String id) {
        exchange.getResponseHeaders().add("Set-Cookie", SESSION_COOKIE + "=" + id + "; Path=/; HttpOnly; SameSite=Lax" + (secureCookies ? "; Secure" : ""));
    }

    private void error(HttpExchange exchange, RanteLoginException error) throws IOException {
        // Log the reason, never the code, the cookies or a token.
        LOG.warning("Sign-in failed: " + error.code() + ": " + error.getMessage());
        String message = "access_denied".equals(error.code()) ? "The sign-in was cancelled on the Rante Login page." : error.getMessage();
        html(exchange, 400, page("Sign-in failed", "<h1>Sign-in failed</h1><p class=\"error\"><code>" + escape(error.code()) + "</code> "
                + escape(message) + "</p><p><a href=\"/\">Try again</a></p>"));
    }

    private String signInPage(String nonce) {
        return page("Sign in with Rante", "<h1>Sign in with Rante</h1>"
                + "<p>JDK HTTP server example of the Rante Login SDK for Java: the server finishes the sign-in and validates the ID token.</p>"
                + "<div id=\"rante-signin\" data-client-id=\"" + escape(rante.clientId()) + "\" data-redirect-uri=\"" + escape(rante.redirectUri())
                + "\" data-scope=\"" + escape(rante.scope()) + "\" data-nonce=\"" + escape(nonce) + "\"></div>"
                + "<p id=\"rante-signin-status\" role=\"status\"></p>"
                + "<p><a href=\"/auth/rante/sign-in\">Sign in without JavaScript</a> (the server starts the sign-in)</p>"
                + "<script src=\"" + SDK_SRC + "\" integrity=\"" + SDK_INTEGRITY + "\" crossorigin=\"anonymous\"></script>"
                + "<script src=\"/signin.js\"></script>");
    }

    private String signedInPage(Session session) {
        Object name = session.claims.get("name");
        return page("Signed in", "<h1>Signed in" + (name == null ? "" : " as " + escape(String.valueOf(name))) + "</h1>"
                + "<p>Signed in with: <strong>" + escape(session.method) + "</strong>, " + session.signedInAt + "</p>"
                + accountSection(session)
                + "<h2>ID token</h2>"
                + "<p>This server validated the ID token below. Use <code>sub</code> as the person's ID on this website: it is pairwise, so other "
                + "organizations' apps see a different value.</p>"
                + table(session.claims)
                + "<p><a href=\"/userinfo\">Show userinfo</a></p>"
                + "<form method=\"post\" action=\"/auth/sign-out\"><button type=\"submit\">Sign out</button></form>");
    }

    private String accountSection(Session session) {
        Account account = accounts.get(String.valueOf(session.claims.get("sub")));
        if (account == null) {
            return "<h2>Your account on this website</h2><p>Not found: this example keeps accounts in memory, and the server has restarted "
                    + "since you signed in. Sign out and in again.</p>";
        }
        String status = session.newAccount
                ? "Created at this sign-in from your Rante account: no separate sign-up form, and no password for this website."
                : "Welcome back: this sign-in found your account by its Rante ID.";
        return "<h2>Your account on this website</h2><p>" + escape(status) + "</p><table><tbody>"
                + "<tr><th>Account ID</th><td>" + escape(account.id()) + "</td></tr>"
                + "<tr><th>Linked Rante ID (<code>sub</code>)</th><td>" + escape(account.sub()) + "</td></tr>"
                + "<tr><th>Name</th><td>" + escape(account.name() != null ? account.name() : "not shared") + "</td></tr>"
                + "<tr><th>Email</th><td>" + escape(account.email() != null ? account.email()
                        : "not shared (Rante shares an email only once it's verified)") + "</td></tr>"
                + "<tr><th>Created</th><td>" + account.createdAt() + "</td></tr>"
                + "<tr><th>Last sign-in</th><td>" + account.lastSignInAt() + "</td></tr>"
                + "</tbody></table>"
                + "<p>This example keeps accounts in memory. A real website stores them in its database, keyed by <code>sub</code>.</p>";
    }

    private static String table(Map<String, Object> claims) {
        StringBuilder rows = new StringBuilder();
        claims.forEach((name, value) -> rows.append("<tr><th><code>").append(escape(name)).append("</code></th><td>")
                .append(escape(value instanceof List<?> list ? JSONArrayUtils.toJSONString(list)
                        : value instanceof Map<?, ?> map ? JSONObjectUtils.toJSONString(stringKeys(map)) : String.valueOf(value)))
                .append("</td></tr>"));
        return "<table><tbody>" + rows + "</tbody></table>";
    }

    private static Map<String, Object> stringKeys(Map<?, ?> map) {
        Map<String, Object> copy = new LinkedHashMap<>();
        map.forEach((key, value) -> copy.put(String.valueOf(key), value));
        return copy;
    }

    private static String page(String title, String body) {
        return "<!doctype html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"utf-8\">\n"
                + "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
                + "  <title>" + escape(title) + " - JDK HTTP server example</title>\n  <link rel=\"stylesheet\" href=\"/style.css\">\n</head>\n"
                + "<body>\n  <main>\n" + body + "\n  </main>\n</body>\n</html>\n";
    }

    private static void asset(HttpExchange exchange, String name) throws IOException {
        try (InputStream stream = ExampleServer.class.getResourceAsStream("/public/" + name)) {
            if (stream == null) {
                exchange.sendResponseHeaders(404, -1);
                return;
            }
            send(exchange, 200, name.endsWith(".js") ? "text/javascript; charset=utf-8" : "text/css; charset=utf-8", stream.readAllBytes());
        }
    }

    private static void html(HttpExchange exchange, int status, String html) throws IOException {
        send(exchange, status, "text/html; charset=utf-8", html.getBytes(StandardCharsets.UTF_8));
    }

    private static void json(HttpExchange exchange, int status, String json) throws IOException {
        send(exchange, status, "application/json", json.getBytes(StandardCharsets.UTF_8));
    }

    private static void send(HttpExchange exchange, int status, String contentType, byte[] body) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", contentType);
        if (exchange.getRequestMethod().equals("HEAD")) {
            exchange.sendResponseHeaders(status, -1); // a HEAD response has no body
            return;
        }
        exchange.sendResponseHeaders(status, body.length);
        exchange.getResponseBody().write(body);
    }

    private static void redirect(HttpExchange exchange, String location) throws IOException {
        exchange.getResponseHeaders().set("Location", location);
        exchange.sendResponseHeaders(303, -1);
    }

    private static String cookie(HttpExchange exchange, String name) {
        Map<String, String> cookies = new LinkedHashMap<>();
        for (String header : exchange.getRequestHeaders().getOrDefault("Cookie", java.util.List.of())) {
            for (String part : header.split(";")) {
                int index = part.indexOf('=');
                if (index > 0) {
                    cookies.putIfAbsent(part.substring(0, index).trim(), part.substring(index + 1).trim());
                }
            }
        }
        return cookies.get(name);
    }

    private static String queryValue(String rawQuery, String name) {
        for (String pair : (rawQuery == null ? "" : rawQuery).split("&")) {
            if (pair.startsWith(name + "=")) {
                return java.net.URLDecoder.decode(pair.substring(name.length() + 1), StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    private static byte[] readAtMost(InputStream stream, int limit) throws IOException {
        byte[] bytes = stream.readNBytes(limit + 1);
        return bytes.length > limit ? null : bytes;
    }

    private static String randomToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String escape(String value) {
        StringBuilder out = new StringBuilder(value.length());
        for (char c : value.toCharArray()) {
            switch (c) {
                case '&' -> out.append("&amp;");
                case '<' -> out.append("&lt;");
                case '>' -> out.append("&gt;");
                case '"' -> out.append("&quot;");
                case '\'' -> out.append("&#39;");
                default -> out.append(c);
            }
        }
        return out.toString();
    }
}
