package com.sricharan.security.autoconfigure.token;

import com.sricharan.security.core.token.RefreshTokenStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Redis-backed refresh-token store for multi-instance deployments.
 *
 * <p>Data model:
 * <ul>
 *   <li>{@code <prefix>:token:<tokenHash>} -> hash(userId, expiresAt, revoked)</li>
 *   <li>{@code <prefix>:user:<userId>:tokens} -> set(tokenHash...)</li>
 * </ul>
 */
public class RedisRefreshTokenStore implements RefreshTokenStore {

    private static final Logger log = LoggerFactory.getLogger(RedisRefreshTokenStore.class);

    private static final String FIELD_USER_ID = "userId";
    private static final String FIELD_EXPIRES_AT = "expiresAt";
    private static final String FIELD_REVOKED = "revoked";

    private static final String REVOKED_FALSE = "0";
    private static final String REVOKED_TRUE = "1";
    private static final String DEFAULT_PREFIX = "security:refresh";

    private static final DefaultRedisScript<Long> ATOMIC_CONSUME_SCRIPT =
            new DefaultRedisScript<>(
                    """
                    local tokenKey = KEYS[1]
                    local nowMs = tonumber(ARGV[1])
                    local tokenHash = ARGV[2]
                    local keyPrefix = ARGV[3]
                    if redis.call('EXISTS', tokenKey) == 0 then
                      return 0
                    end
                    local userId = redis.call('HGET', tokenKey, 'userId')
                    local expiresAt = tonumber(redis.call('HGET', tokenKey, 'expiresAt') or '0')
                    if expiresAt > 0 and nowMs > expiresAt then
                      redis.call('DEL', tokenKey)
                      if userId then
                        redis.call('SREM', keyPrefix .. ':user:' .. userId .. ':tokens', tokenHash)
                      end
                      return 0
                    end
                    local revoked = redis.call('HGET', tokenKey, 'revoked')
                    if revoked == '1' then
                      return -1
                    end
                    redis.call('HSET', tokenKey, 'revoked', '1')
                    return 1
                    """,
                    Long.class
            );

    private final StringRedisTemplate redisTemplate;
    private final String keyPrefix;

    public RedisRefreshTokenStore(StringRedisTemplate redisTemplate, String keyPrefix) {
        this.redisTemplate = redisTemplate;
        this.keyPrefix = normalizePrefix(keyPrefix);
    }

    @Override
    public void store(String userId, String tokenHash, Instant expiresAt) {
        Duration ttl = Duration.between(Instant.now(), expiresAt);
        if (ttl.isNegative() || ttl.isZero()) {
            return;
        }

        String tokenKey = tokenKey(tokenHash);
        String userTokensKey = userTokensKey(userId);

        Map<String, String> payload = new HashMap<>();
        payload.put(FIELD_USER_ID, userId);
        payload.put(FIELD_EXPIRES_AT, String.valueOf(expiresAt.toEpochMilli()));
        payload.put(FIELD_REVOKED, REVOKED_FALSE);

        redisTemplate.opsForHash().putAll(tokenKey, payload);
        redisTemplate.expire(tokenKey, ttl);

        redisTemplate.opsForSet().add(userTokensKey, tokenHash);
        extendUserIndexTtl(userTokensKey, ttl);
    }

    @Override
    public boolean isValid(String tokenHash) {
        String tokenKey = tokenKey(tokenHash);
        Map<Object, Object> data = redisTemplate.opsForHash().entries(tokenKey);
        if (data == null || data.isEmpty()) {
            return false;
        }

        String userId = asString(data.get(FIELD_USER_ID));
        if (userId == null || userId.isBlank()) {
            return false;
        }

        if (REVOKED_TRUE.equals(asString(data.get(FIELD_REVOKED)))) {
            log.warn("Revoked refresh token reuse detected for user '{}'. This may indicate token theft — revoking ALL tokens for this user.", userId);
            revokeAllForUser(userId);
            return false;
        }

        long expiresAtMs = parseLong(asString(data.get(FIELD_EXPIRES_AT)));
        if (expiresAtMs > 0 && Instant.now().toEpochMilli() > expiresAtMs) {
            redisTemplate.delete(tokenKey);
            redisTemplate.opsForSet().remove(userTokensKey(userId), tokenHash);
            return false;
        }

        return true;
    }

    @Override
    public boolean consumeForRotation(String tokenHash) {
        Long result = redisTemplate.execute(
                ATOMIC_CONSUME_SCRIPT,
                List.of(tokenKey(tokenHash)),
                String.valueOf(Instant.now().toEpochMilli()),
                tokenHash,
                keyPrefix
        );

        if (result == null || result == 0L) {
            return false;
        }

        if (result == 1L) {
            return true;
        }

        if (result == -1L) {
            String userId = asString(redisTemplate.opsForHash().get(tokenKey(tokenHash), FIELD_USER_ID));
            if (userId != null && !userId.isBlank()) {
                log.warn("Revoked refresh token replay detected for user '{}'. Revoking all active refresh tokens.", userId);
                revokeAllForUser(userId);
            }
            return false;
        }

        return false;
    }

    @Override
    public void revoke(String tokenHash) {
        String tokenKey = tokenKey(tokenHash);
        if (Boolean.TRUE.equals(redisTemplate.hasKey(tokenKey))) {
            redisTemplate.opsForHash().put(tokenKey, FIELD_REVOKED, REVOKED_TRUE);
        }
    }

    @Override
    public void revokeAllForUser(String userId) {
        String userTokensKey = userTokensKey(userId);
        Set<String> tokenHashes = redisTemplate.opsForSet().members(userTokensKey);
        if (tokenHashes != null && !tokenHashes.isEmpty()) {
            List<String> tokenKeys = tokenHashes.stream().map(this::tokenKey).toList();
            redisTemplate.delete(tokenKeys);
        }
        redisTemplate.delete(userTokensKey);
    }

    private String tokenKey(String tokenHash) {
        return keyPrefix + ":token:" + tokenHash;
    }

    private String userTokensKey(String userId) {
        return keyPrefix + ":user:" + userId + ":tokens";
    }

    private void extendUserIndexTtl(String userTokensKey, Duration ttl) {
        long requestedSeconds = Math.max(ttl.getSeconds(), 1L);
        Long currentTtl = redisTemplate.getExpire(userTokensKey, TimeUnit.SECONDS);
        if (currentTtl == null || currentTtl < requestedSeconds) {
            redisTemplate.expire(userTokensKey, Duration.ofSeconds(requestedSeconds));
        }
    }

    private static String normalizePrefix(String rawPrefix) {
        if (rawPrefix == null || rawPrefix.isBlank()) {
            return DEFAULT_PREFIX;
        }
        String trimmed = rawPrefix.trim();
        if (trimmed.endsWith(":")) {
            return trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }

    private static String asString(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private static long parseLong(String value) {
        if (value == null || value.isBlank()) {
            return 0L;
        }
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException ignored) {
            return 0L;
        }
    }
}
