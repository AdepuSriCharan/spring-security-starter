package com.sricharan.security.core.token;

import java.time.Instant;

/**
 * Public view of an active refresh-token-backed session.
 *
 * <p>The session identifier is the token hash managed by {@link RefreshTokenStore}.
 * Raw tokens are never exposed by this model.
 */
public record RefreshSession(
        String sessionId,
        String userId,
        Instant expiresAt
) {
}
