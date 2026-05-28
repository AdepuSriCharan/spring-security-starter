package com.sricharan.security.core.identity;

import java.util.Collections;
import java.util.Map;

/**
 * Normalized profile returned by an external identity provider.
 *
 * <p>The starter uses this to turn a federated identity assertion
 * (for example a Google ID token) into a local application user.
 */
public record ExternalIdentityProfile(
        String provider,
        String subject,
        String email,
        boolean emailVerified,
        String displayName,
        Map<String, Object> claims
) {

    public ExternalIdentityProfile {
        claims = claims == null ? Collections.emptyMap() : Collections.unmodifiableMap(claims);
    }
}
