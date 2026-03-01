package com.sricharan.security.autoconfigure.token;

import com.sricharan.security.core.token.RefreshTokenStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Default in-memory implementation of {@link RefreshTokenStore}.
 *
 * <p>Suitable for development, testing, and single-instance deployments.
 * Token data is lost on application restart.
 *
 * <p>For production multi-instance deployments, replace this bean with a
 * JPA-backed or Redis-backed implementation.
 *
 * <p><strong>Thread safety:</strong> Uses {@link ConcurrentHashMap} for safe concurrent access.
 */
public class InMemoryRefreshTokenStore implements RefreshTokenStore {

    private static final Logger log = LoggerFactory.getLogger(InMemoryRefreshTokenStore.class);

    /**
     * Internal record representing a stored refresh token entry.
     */
    private record TokenEntry(String userId, Instant expiresAt, boolean revoked) {}

    private final Map<String, TokenEntry> tokens = new ConcurrentHashMap<>();

    @Override
    public void store(String userId, String tokenHash, Instant expiresAt) {
        tokens.put(tokenHash, new TokenEntry(userId, expiresAt, false));
        purgeExpired();
        log.debug("Stored refresh token for user '{}'. Active tokens: {}", userId, tokens.size());
    }

    @Override
    public boolean isValid(String tokenHash) {
        TokenEntry entry = tokens.get(tokenHash);
        if (entry == null) {
            return false;
        }
        if (entry.revoked()) {
            log.warn("Revoked refresh token reuse detected for user '{}'. " +
                     "This may indicate token theft — revoking ALL tokens for this user.", entry.userId());
            revokeAllForUser(entry.userId());
            return false;
        }
        if (Instant.now().isAfter(entry.expiresAt())) {
            tokens.remove(tokenHash);
            return false;
        }
        return true;
    }

    @Override
    public void revoke(String tokenHash) {
        TokenEntry entry = tokens.get(tokenHash);
        if (entry != null) {
            // Mark as revoked instead of removing — allows replay detection
            tokens.put(tokenHash, new TokenEntry(entry.userId(), entry.expiresAt(), true));
            log.debug("Revoked refresh token for user '{}'", entry.userId());
        }
    }

    @Override
    public void revokeAllForUser(String userId) {
        tokens.entrySet().removeIf(e -> e.getValue().userId().equals(userId));
        log.info("Revoked ALL refresh tokens for user '{}'", userId);
    }

    /**
     * Removes expired entries to prevent unbounded memory growth.
     */
    private void purgeExpired() {
        Instant now = Instant.now();
        tokens.entrySet().removeIf(e -> now.isAfter(e.getValue().expiresAt()));
    }
}
