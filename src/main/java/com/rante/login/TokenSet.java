package com.rante.login;

/**
 * The token endpoint's answer.
 *
 * @param accessToken for the userinfo endpoint (15 minutes)
 * @param tokenType {@code Bearer}
 * @param expiresIn the access token's lifetime in seconds, or null
 * @param idToken the ID token, before validation
 * @param scope the granted scopes, or null
 */
public record TokenSet(String accessToken, String tokenType, Long expiresIn, String idToken, String scope) {
}
