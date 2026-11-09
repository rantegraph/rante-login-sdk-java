package com.rante.login;

/**
 * Options for {@link RanteLoginClient#createAuthorizationRequest(AuthorizationRequestOptions)}. Every field may be
 * null.
 *
 * @param nonce your own nonce (default: a random one)
 * @param prompt {@code none}, {@code login}, {@code consent} or {@code select_account}
 * @param loginHint a suggested account, up to 256 characters
 * @param maxAge the maximum authentication age, in seconds
 */
public record AuthorizationRequestOptions(String nonce, String prompt, String loginHint, Integer maxAge) {
    /** No options. */
    public static AuthorizationRequestOptions none() {
        return new AuthorizationRequestOptions(null, null, null, null);
    }
}
