package com.rante.login;

import java.util.Map;

/**
 * The userinfo endpoint's answer.
 *
 * @param subject the person's pairwise ID
 * @param claims the claims, by name
 */
public record UserInfo(String subject, Map<String, Object> claims) {
    public UserInfo {
        claims = java.util.Collections.unmodifiableMap(new java.util.LinkedHashMap<>(claims));
    }
}
