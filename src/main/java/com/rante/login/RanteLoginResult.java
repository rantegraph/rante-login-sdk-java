package com.rante.login;

import java.util.Map;

/**
 * A finished sign-in: the validated ID token and the token response.
 *
 * @param idToken the validated ID token
 * @param tokens the token response
 */
public record RanteLoginResult(ValidatedIdToken idToken, TokenSet tokens) {
    /** The person's pairwise ID. */
    public String subject() {
        return idToken.subject();
    }

    /** The ID token's claims. */
    public Map<String, Object> claims() {
        return idToken.claims();
    }

    /** The access token for the userinfo endpoint (15 minutes). */
    public String accessToken() {
        return tokens.accessToken();
    }
}
