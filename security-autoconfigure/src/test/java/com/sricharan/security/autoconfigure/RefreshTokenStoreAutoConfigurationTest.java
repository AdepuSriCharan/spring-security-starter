package com.sricharan.security.autoconfigure;

import com.sricharan.security.autoconfigure.token.InMemoryRefreshTokenStore;
import com.sricharan.security.autoconfigure.token.RedisRefreshTokenStore;
import com.sricharan.security.core.token.RefreshTokenStore;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.web.SecurityFilterChain;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

@Testcontainers
class RefreshTokenStoreAutoConfigurationTest {

    @Container
    static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
            .withExposedPorts(6379);

    private static final String JWT_SECRET = "12345678901234567890123456789012";

    @Test
    void defaultConfigurationUsesInMemoryStore() {
        ApplicationContextRunner runner = baseRunner()
                .withConfiguration(AutoConfigurations.of(
                        SecurityAutoConfiguration.class,
                        RedisRefreshTokenAutoConfiguration.class))
                .withPropertyValues("security.jwt.secret=" + JWT_SECRET);

        runner.run(context -> {
            assertThat(context).hasSingleBean(RefreshTokenStore.class);
            assertThat(context.getBean(RefreshTokenStore.class)).isInstanceOf(InMemoryRefreshTokenStore.class);
        });
    }

    @Test
    void redisModeUsesRedisStoreWhenRedisIsAvailable() {
        ApplicationContextRunner runner = baseRunner()
                .withConfiguration(AutoConfigurations.of(
                        RedisAutoConfiguration.class,
                        SecurityAutoConfiguration.class,
                        RedisRefreshTokenAutoConfiguration.class))
                .withPropertyValues(
                        "security.jwt.secret=" + JWT_SECRET,
                        "security.refresh.store-mode=REDIS",
                        "spring.data.redis.host=" + REDIS.getHost(),
                        "spring.data.redis.port=" + REDIS.getMappedPort(6379));

        runner.run(context -> {
            assertThat(context).hasSingleBean(RefreshTokenStore.class);
            assertThat(context.getBean(RefreshTokenStore.class)).isInstanceOf(RedisRefreshTokenStore.class);
        });
    }

    @Test
    void redisModeFailsFastWhenRedisSupportMissing() {
        ApplicationContextRunner runner = baseRunner()
                .withClassLoader(new FilteredClassLoader("org.springframework.data.redis"))
                .withConfiguration(AutoConfigurations.of(SecurityAutoConfiguration.class))
                .withPropertyValues(
                        "security.jwt.secret=" + JWT_SECRET,
                        "security.refresh.store-mode=REDIS");

        runner.run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .hasRootCauseMessage("security.refresh.store-mode=REDIS requires Redis support on the classpath.\n"
                            + "Add dependency: org.springframework.boot:spring-boot-starter-data-redis");
        });
    }

    private ApplicationContextRunner baseRunner() {
        return new ApplicationContextRunner()
                .withBean(SecurityFilterChain.class, () -> mock(SecurityFilterChain.class));
    }
}
