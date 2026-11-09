package com.rante.login;

import java.util.List;

/** The cookies the Rante Login browser SDK writes with {@code serverSide: true} (SameSite=Lax, 10 minutes, Path=/). */
public final class BrowserSdkCookies {
    /** The PKCE verifier. */
    public static final String CODE_VERIFIER = "rante_login_pkce";
    /** The state. */
    public static final String STATE = "rante_login_state";
    /** The nonce. */
    public static final String NONCE = "rante_login_nonce";
    /** All three, for clearing them once read: each sign-in uses them once. */
    public static final List<String> ALL = List.of(CODE_VERIFIER, STATE, NONCE);

    private BrowserSdkCookies() {
    }
}
