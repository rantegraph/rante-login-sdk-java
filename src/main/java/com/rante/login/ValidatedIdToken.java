package com.rante.login;

import java.util.Map;

/**
 * A validated ID token.
 *
 * @param subject the person's ID on your website: pairwise, so the same for your organization's apps and different
 *     for other organizations
 * @param claims the token's claims as its JSON payload has them, by their JWT names: strings, numbers (times are seconds
 *     since the epoch), booleans, lists and maps
 */
public record ValidatedIdToken(String subject, Map<String, Object> claims) {
    public ValidatedIdToken {
        claims = java.util.Collections.unmodifiableMap(new java.util.LinkedHashMap<>(claims));
    }
}
