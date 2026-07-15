# Auto-Configuration Internals

This document explains how Spring Security Explainer integrates with Spring Boot's auto-configuration mechanism — useful for contributors and developers who want to understand why certain beans are or are not created.

---

## Registration

Spring Boot discovers auto-configuration classes via the `AutoConfiguration.imports` file at:

```
security-autoconfigure/src/main/resources/
  META-INF/spring/
    org.springframework.boot.autoconfigure.AutoConfiguration.imports
```

Contents:
```
com.sricharan.security.autoconfigure.SecurityAutoConfiguration
com.sricharan.security.autoconfigure.RedisRefreshTokenAutoConfiguration
com.sricharan.security.autoconfigure.ExternalProviderAutoConfiguration
```

All three classes are loaded by Spring Boot's auto-configuration mechanism on startup.

---

## `SecurityAutoConfiguration` — The Core Class

This is the main configuration class. It activates for every application that includes the starter on the classpath.

### Startup Validation (`@PostConstruct`)

Before any beans are created, the `@PostConstruct` method `validateExternalProviderConfig()` runs and verifies:
- If `auth-mode=OAUTH2` or `KEYCLOAK`: that `issuer-uri` or `jwk-set-uri` is configured
- If `auth-mode=INTERNAL` with `store-mode=REDIS`: that the Redis class is on the classpath

These fail fast with a clear `IllegalStateException`.

### Universal Beans (All Modes)

These beans are created regardless of auth mode:

| Bean | Type | Condition |
|---|---|---|
| `authorizationManager` | `DefaultAuthorizationManager` | `@ConditionalOnMissingBean` |
| `springSecurityAuthenticationAdapter` | `SpringSecurityAuthenticationAdapter` | `@ConditionalOnMissingBean` |
| `securityContextFilter` | `SecurityContextFilter` | `@ConditionalOnMissingBean` |
| `authorizationAspect` | `AuthorizationAspect` | `@ConditionalOnMissingBean` |
| `securityExceptionHandler` | `SecurityExceptionHandler` | `@ConditionalOnMissingBean` |
| `authenticationEntryPoint` | `JsonAuthenticationEntryPoint` | `@ConditionalOnMissingBean` |
| `accessDeniedHandler` | `JsonAccessDeniedHandler` | `@ConditionalOnMissingBean` |
| `passwordEncoder` | `BCryptPasswordEncoder` | `@ConditionalOnMissingBean` |
| `securityAuditSink` | `JsonSecurityAuditSink` (or no-op) | `@ConditionalOnMissingBean` |
| `securityMetricsRecorder` | `MicrometerSecurityMetricsRecorder` or `NoOpSecurityMetricsRecorder` | `@ConditionalOnMissingBean` |
| `securityEventRecorder` | `SecurityEventRecorder` | `@ConditionalOnMissingBean` |

### INTERNAL Mode Beans

These beans are only created when `security.auth-mode=INTERNAL` (or auth-mode is not set, since INTERNAL is the default):

| Bean | Condition |
|---|---|
| `jwtService` | `@ConditionalOnProperty(auth-mode=INTERNAL)` + `@ConditionalOnMissingBean` |
| `jwtAuthenticationAdapter` | `@ConditionalOnProperty(auth-mode=INTERNAL)` |
| `jwtAuthenticationFilter` | `@ConditionalOnProperty(auth-mode=INTERNAL)` |
| `refreshTokenStore` (InMemory) | `@ConditionalOnProperty(auth-mode=INTERNAL)` + `store-mode=INMEMORY` + `@ConditionalOnMissingBean` |
| `authController` | `@ConditionalOnProperty(auth-mode=INTERNAL)` + `@ConditionalOnBean(UserAccountProvider.class)` + `@ConditionalOnMissingBean` |
| `internalSecurityFilterChain` | `@ConditionalOnProperty(auth-mode=INTERNAL)` + `@ConditionalOnMissingBean` |

> **Note:** `authController` requires a `UserAccountProvider` bean to exist. If no `UserAccountProvider` is declared, `AuthController` is not registered and `/login` returns `501 NOT_IMPLEMENTED`.

---

## `RedisRefreshTokenAutoConfiguration`

Activated when **all three** conditions are true:
1. `org.springframework.data.redis.core.StringRedisTemplate` is on the classpath (`@ConditionalOnClass`)
2. `security.refresh.store-mode=REDIS` (`@ConditionalOnProperty`)
3. `security.auth-mode=INTERNAL` (via `@ConditionalOnExpression`)

```java
@AutoConfiguration(after = SecurityAutoConfiguration.class)
@ConditionalOnClass(name = "org.springframework.data.redis.core.StringRedisTemplate")
@ConditionalOnProperty(prefix = "security.refresh", name = "store-mode", havingValue = "REDIS")
@ConditionalOnExpression("'${security.auth-mode:INTERNAL}'.equals('INTERNAL')")
public class RedisRefreshTokenAutoConfiguration {
    // ...
}
```

On activation, it:
1. Retrieves the `StringRedisTemplate` bean
2. Pings Redis via the connection factory
3. Throws `IllegalStateException` if Redis is unreachable
4. Creates `RedisRefreshTokenStore`

---

## `ExternalProviderAutoConfiguration`

Activated when `BearerTokenAuthenticationFilter` is on the classpath (i.e., when `spring-boot-starter-oauth2-resource-server` is added):

```java
@AutoConfiguration(after = SecurityAutoConfiguration.class)
@ConditionalOnClass(BearerTokenAuthenticationFilter.class)
public class ExternalProviderAutoConfiguration {
    // OAUTH2 and KEYCLOAK beans
}
```

This class is guarded by `@ConditionalOnClass` specifically to prevent `ClassNotFoundException` when the OAuth2 dependency is absent. In INTERNAL mode, users do not need that dependency, so this class must not attempt to reference any of its classes.

### OAUTH2 beans

Created when `security.auth-mode=OAUTH2`:
- `oauth2AuthenticationAdapter` (`OAuth2AuthenticationAdapter`)
- `oauth2SecurityFilterChain` (`SecurityFilterChain`)

### KEYCLOAK beans

Created when `security.auth-mode=KEYCLOAK`:
- `keycloakAuthenticationAdapter` (`KeycloakAuthenticationAdapter`)
- `keycloakSecurityFilterChain` (`SecurityFilterChain`)

---

## Micrometer — Optional Dependency Handling

Micrometer is not declared as a required dependency. The starter uses reflection to detect it at runtime:

```java
@Bean
@ConditionalOnMissingBean
public SecurityMetricsRecorder securityMetricsRecorder(ApplicationContext applicationContext) {
    try {
        Class<?> meterRegistryClass = Class.forName("io.micrometer.core.instrument.MeterRegistry");
        Object meterRegistry = applicationContext.getBeanProvider(meterRegistryClass).getIfAvailable();
        if (meterRegistry == null) {
            return new NoOpSecurityMetricsRecorder();
        }
        // instantiate MicrometerSecurityMetricsRecorder via reflection
        ...
    } catch (ClassNotFoundException e) {
        return new NoOpSecurityMetricsRecorder();
    }
}
```

This pattern avoids a hard compile-time dependency on Micrometer while still supporting it when present.

---

## `AuthorizationAspect` — AOP Wiring

`AuthorizationAspect` is an `@Aspect` class registered as a Spring bean. It is auto-detected by Spring's AOP proxy infrastructure because:
1. `spring-boot-starter-aop` includes `spring-aop` and AspectJ weaver
2. The `@Aspect` class is registered as a regular Spring bean in `SecurityAutoConfiguration`

Spring Boot auto-configuration enables `@EnableAspectJAutoProxy` by default when `spring-aop` is present.

---

## Bean Override Example

To replace any default bean, declare a `@Bean` method in your `@Configuration` class that returns the same type:

```java
@Configuration
public class MySecurityConfig {

    // Replaces BCryptPasswordEncoder
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new Argon2PasswordEncoder(16, 32, 1, 65536, 10);
    }
}
```

Spring Boot's auto-configuration runs **after** your application configuration. Since `SecurityAutoConfiguration.passwordEncoder()` has `@ConditionalOnMissingBean`, it detects your bean and skips creating its own.
