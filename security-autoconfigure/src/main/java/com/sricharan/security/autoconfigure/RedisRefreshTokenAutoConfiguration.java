package com.sricharan.security.autoconfigure;

import com.sricharan.security.autoconfigure.config.SecurityProperties;
import com.sricharan.security.autoconfigure.token.RedisRefreshTokenStore;
import com.sricharan.security.core.config.AuthMode;
import com.sricharan.security.core.token.RefreshTokenStore;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * Redis-backed refresh-token store auto-configuration.
 */
@AutoConfiguration(after = SecurityAutoConfiguration.class)
@ConditionalOnClass(name = "org.springframework.data.redis.core.StringRedisTemplate")
@ConditionalOnProperty(prefix = "security.refresh", name = "store-mode", havingValue = "REDIS")
@ConditionalOnExpression("'${security.auth-mode:INTERNAL}'.equals('INTERNAL')")
public class RedisRefreshTokenAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(RefreshTokenStore.class)
    public RefreshTokenStore redisRefreshTokenStore(
            ObjectProvider<StringRedisTemplate> redisTemplateProvider,
            SecurityProperties securityProperties) {

        if (securityProperties.getAuthMode() != AuthMode.INTERNAL) {
            throw new IllegalStateException("Redis refresh-token store is only supported for security.auth-mode=INTERNAL.");
        }

        StringRedisTemplate redisTemplate = redisTemplateProvider.getIfAvailable();
        if (redisTemplate == null) {
            throw new IllegalStateException(
                    "security.refresh.store-mode=REDIS is enabled, but no StringRedisTemplate bean was found.\n"
                            + "Add org.springframework.boot:spring-boot-starter-data-redis and configure spring.data.redis.*");
        }

        RedisConnectionFactory connectionFactory = redisTemplate.getConnectionFactory();
        if (connectionFactory == null) {
            throw new IllegalStateException(
                    "security.refresh.store-mode=REDIS is enabled, but no RedisConnectionFactory is configured.");
        }

        try (RedisConnection connection = connectionFactory.getConnection()) {
            connection.ping();
        } catch (Exception ex) {
            throw new IllegalStateException(
                    "security.refresh.store-mode=REDIS is enabled, but Redis is not reachable.\n"
                            + "Check spring.data.redis.host/port and Redis availability.", ex);
        }

        return new RedisRefreshTokenStore(
                redisTemplate,
                securityProperties.getRefresh().getRedis().getKeyPrefix());
    }
}
