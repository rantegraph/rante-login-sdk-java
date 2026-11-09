package com.rante.login;

/** What a sign-in must match at the redirect URI: its state, nonce and PKCE code verifier. */
public record ExpectedTransaction(String state, String nonce, String codeVerifier) {
}
