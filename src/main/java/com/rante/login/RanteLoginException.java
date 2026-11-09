package com.rante.login;

/**
 * Every failure the SDK reports. {@link #code()} is stable and safe to show; OAuth errors (access_denied,
 * invalid_grant, invalid_client, ...) keep their own codes.
 */
public final class RanteLoginException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final String code;
    private final Integer status;

    public RanteLoginException(String code, String message) {
        this(code, message, null, null);
    }

    public RanteLoginException(String code, String message, Integer status, Throwable cause) {
        super(message == null || message.isEmpty() ? code : message, cause);
        this.code = code;
        this.status = status;
    }

    /** For example {@code state_mismatch}, {@code invalid_grant} or {@code invalid_id_token}. */
    public String code() {
        return code;
    }

    /** The HTTP status, for errors that came from Rante Login; otherwise null. */
    public Integer status() {
        return status;
    }
}
