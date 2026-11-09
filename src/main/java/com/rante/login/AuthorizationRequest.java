package com.rante.login;

/**
 * A sign-in the server starts: send the browser to {@link #url()}, and keep {@link #state()}, {@link #nonce()} and
 * {@link #codeVerifier()} on the server until it comes back to the redirect URI.
 */
public record AuthorizationRequest(String url, String state, String nonce, String codeVerifier) {
    /** What the sign-in must match at the redirect URI. */
    public ExpectedTransaction toExpected() {
        return new ExpectedTransaction(state, nonce, codeVerifier);
    }
}
