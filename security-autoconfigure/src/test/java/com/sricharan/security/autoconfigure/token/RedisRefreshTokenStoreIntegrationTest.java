package com.sricharan.security.autoconfigure.token;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;

@Testcontainers
class RedisRefreshTokenStoreIntegrationTest {

    @Container
    static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
            .withExposedPorts(6379);

    private LettuceConnectionFactory connectionFactory;

    @AfterEach
    void tearDown() {
        if (connectionFactory != null) {
            connectionFactory.destroy();
        }
    }

    @Test
    void storeAndValidateToken() {
        RedisRefreshTokenStore store = newStore();

        store.store("user-1", "token-a", Instant.now().plusSeconds(60));

        assertThat(store.isValid("token-a")).isTrue();
    }

    @Test
    void rotateOnceAndRejectOldToken() {
        RedisRefreshTokenStore store = newStore();
        store.store("user-1", "token-a", Instant.now().plusSeconds(60));

        assertThat(store.consumeForRotation("token-a")).isTrue();
        assertThat(store.consumeForRotation("token-a")).isFalse();
    }

    @Test
    void replayedRevokedTokenRevokesAllUserTokens() {
        RedisRefreshTokenStore store = newStore();
        store.store("user-1", "token-a", Instant.now().plusSeconds(60));
        store.store("user-1", "token-b", Instant.now().plusSeconds(60));

        assertThat(store.consumeForRotation("token-a")).isTrue();
        assertThat(store.consumeForRotation("token-a")).isFalse();
        assertThat(store.isValid("token-b")).isFalse();
    }

    @Test
    void logoutRevokeInvalidatesToken() {
        RedisRefreshTokenStore store = newStore();
        store.store("user-1", "token-a", Instant.now().plusSeconds(60));

        store.revoke("token-a");

        assertThat(store.isValid("token-a")).isFalse();
    }

    @Test
    void revokeAllForUserOnlyAffectsThatUser() {
        RedisRefreshTokenStore store = newStore();
        store.store("user-1", "token-a", Instant.now().plusSeconds(60));
        store.store("user-2", "token-b", Instant.now().plusSeconds(60));

        store.revokeAllForUser("user-1");

        assertThat(store.isValid("token-a")).isFalse();
        assertThat(store.isValid("token-b")).isTrue();
    }

    @Test
    void concurrentConsumeAllowsExactlyOneWinner() throws Exception {
        RedisRefreshTokenStore store = newStore();
        store.store("user-1", "token-a", Instant.now().plusSeconds(60));

        int attempts = 20;
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Future<Boolean>> futures = new ArrayList<>();
            for (int i = 0; i < attempts; i++) {
                Callable<Boolean> task = () -> {
                    start.await();
                    return store.consumeForRotation("token-a");
                };
                futures.add(pool.submit(task));
            }

            start.countDown();

            int successCount = 0;
            for (Future<Boolean> future : futures) {
                if (future.get()) {
                    successCount++;
                }
            }

            assertThat(successCount).isEqualTo(1);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void ttlExpiryInvalidatesToken() throws Exception {
        RedisRefreshTokenStore store = newStore();
        store.store("user-1", "token-a", Instant.now().plusSeconds(1));

        Thread.sleep(1300L);

        assertThat(store.isValid("token-a")).isFalse();
    }

    private RedisRefreshTokenStore newStore() {
        connectionFactory = new LettuceConnectionFactory(REDIS.getHost(), REDIS.getMappedPort(6379));
        connectionFactory.afterPropertiesSet();

        StringRedisTemplate redisTemplate = new StringRedisTemplate(connectionFactory);
        redisTemplate.afterPropertiesSet();
        try (RedisConnection connection = redisTemplate.getConnectionFactory().getConnection()) {
            connection.serverCommands().flushDb();
        }

        return new RedisRefreshTokenStore(redisTemplate, "test:refresh");
    }
}
