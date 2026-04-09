package com.sricharan.security.core.token;

import java.time.Instant;

/**
 * Service Provider Interface (SPI) for refresh token storage and lifecycle management.
 *
 * <p>The security framework uses this abstraction to support <strong>refresh token rotation</strong>:
 * every time a refresh token is exchanged for a new access/refresh pair, the old token is revoked
 * and a new one is stored. If a revoked token is reused, it signals a potential theft and all
 * tokens for the affected user are revoked.
 *
 * <p><strong>Implementations:</strong>
 * <ul>
 *   <li>{@code InMemoryRefreshTokenStore} — Default, suitable for development and single-instance deployments</li>
 *   <li>JPA-backed implementation — For production multi-instance deployments (bring your own)</li>
 *   <li>Redis-backed implementation — For high-throughput stateless deployments (bring your own)</li>
 * </ul>
 *
 * <p><strong>Security contract:</strong> Implementations must NEVER store raw tokens.
 * All tokens are hashed (SHA-256) before being passed to this interface.
 *
 * @see com.sricharan.security.core.account.UserAccountProvider
 */
public interface RefreshTokenStore {

    /**
     * Stores a hashed refresh token associated with a user.
     *
     * @param userId    The user's unique identifier.
     * @param tokenHash SHA-256 hash of the raw refresh token.
     * @param expiresAt When this token naturally expires.
     */
    void store(String userId, String tokenHash, Instant expiresAt);

    /**
     * Checks whether a hashed refresh token is valid (exists and not revoked).
     *
     * @param tokenHash SHA-256 hash of the raw refresh token.
     * @return {@code true} if the token exists, is not revoked, and has not expired.
     */
    boolean isValid(String tokenHash);

    /**
     * Atomically consumes a refresh token for rotation.
     *
     * <p>Contract:
     * <ul>
     *   <li>Returns {@code true} only once for a valid token.</li>
     *   <li>Marks that token as revoked so reuse is rejected.</li>
     *   <li>Returns {@code false} if missing, expired, already revoked, or replayed.</li>
     * </ul>
     *
     * <p>Default implementation preserves backward compatibility for existing stores.
     * High-concurrency stores (for example Redis) should override with an atomic implementation.
     *
     * @param tokenHash SHA-256 hash of the raw refresh token.
     * @return {@code true} if the token was valid and successfully consumed for rotation.
     */
    default boolean consumeForRotation(String tokenHash) {
        if (!isValid(tokenHash)) {
            return false;
        }
        revoke(tokenHash);
        return true;
    }

    /**
     * Revokes a single refresh token by its hash.
     *
     * <p>Called during token rotation to invalidate the old token.
     *
     * @param tokenHash SHA-256 hash of the raw refresh token to revoke.
     */
    void revoke(String tokenHash);

    /**
     * Revokes ALL refresh tokens for a given user.
     *
     * <p>Called during logout or when a stolen token replay is detected,
     * to force re-authentication on all devices.
     *
     * @param userId The user whose tokens should all be revoked.
     */
    void revokeAllForUser(String userId);
}
