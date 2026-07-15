# Architecture

This document describes the internal architecture of Spring Security Explainer — how the modules are organised, how control flows through the library, and which components are responsible for each concern.

---

## Module Layout

Spring Security Explainer follows the standard Spring Boot starter module pattern: a separate API module (`security-core`), an auto-configuration module (`security-autoconfigure`), and a thin starter aggregator (`security-starter`).

```
spring-security-explainer/
│
├── security-core/                  ← Public API: interfaces, annotations, model
│   └── src/main/java/com/sricharan/security/core/
│       ├── account/
│       │   ├── UserAccount.java            SPI — implement to describe your users
│       │   └── UserAccountProvider.java    SPI — implement to load users
│       ├── adapter/
│       │   └── AuthenticationAdapter.java  SPI — bridge any auth to AuthenticatedUser
│       ├── annotation/
│       │   ├── RequireRole.java
│       │   ├── RequirePermission.java
│       │   └── RequireOwner.java
│       ├── audit/
│       │   ├── SecurityAuditEvent.java     Structured audit event record
│       │   ├── SecurityAuditEventType.java Enum of all event types
│       │   └── SecurityAuditSink.java      SPI — implement to route events
│       ├── authorization/
│       │   ├── AuthorizationManager.java   SPI — implement for custom authz logic
│       │   └── DefaultAuthorizationManager.java
│       ├── config/
│       │   └── AuthMode.java               INTERNAL | OAUTH2 | KEYCLOAK
│       ├── context/
│       │   └── SecurityUserContext.java    ThreadLocal holder for AuthenticatedUser
│       ├── exception/
│       │   └── SecurityAuthorizationException.java
│       └── user/
│           └── AuthenticatedUser.java      Universal identity model
│
├── security-autoconfigure/         ← Spring Boot auto-configuration (implementation)
│   └── src/main/java/com/sricharan/security/autoconfigure/
│       ├── SecurityAutoConfiguration.java           Main auto-config class
│       ├── ExternalProviderAutoConfiguration.java   OAUTH2/KEYCLOAK wiring
│       ├── RedisRefreshTokenAutoConfiguration.java  Redis token store wiring
│       ├── adapter/
│       │   ├── JwtAuthenticationAdapter.java
│       │   ├── OAuth2AuthenticationAdapter.java
│       │   ├── KeycloakAuthenticationAdapter.java
│       │   └── SpringSecurityAuthenticationAdapter.java
│       ├── aspect/
│       │   └── AuthorizationAspect.java    AOP interceptor for @Require* annotations
│       ├── config/
│       │   └── SecurityProperties.java     @ConfigurationProperties binding
│       ├── controller/
│       │   └── AuthController.java         /login /refresh /logout endpoints
│       ├── filter/
│       │   ├── JwtAuthenticationFilter.java
│       │   └── SecurityContextFilter.java
│       ├── handler/
│       │   ├── JsonAccessDeniedHandler.java
│       │   ├── JsonAuthenticationEntryPoint.java
│       │   └── SecurityExceptionHandler.java
│       ├── jwt/
│       │   ├── JwtAuthenticationToken.java
│       │   ├── JwtProperties.java
│       │   ├── JwtService.java
│       │   └── TokenResponse.java
│       ├── observability/
│       │   ├── JsonSecurityAuditSink.java
│       │   ├── MicrometerSecurityMetricsRecorder.java
│       │   ├── NoOpSecurityMetricsRecorder.java
│       │   ├── SecurityEventRecorder.java
│       │   └── SecurityMetricsRecorder.java
│       ├── token/
│       │   ├── InMemoryRefreshTokenStore.java
│       │   ├── RedisRefreshTokenStore.java
│       │   └── TokenHashUtil.java
│       └── util/
│           └── SpelExpressionEvaluator.java
│
├── security-starter/               ← Thin BOM / aggregator (single import dependency)
│
├── security-test/                  ← Integration test harness
│
└── testing-security-explainer/     ← Reference demo application (PostgreSQL + JPA)
```

---

## Design Principles

### 1. `@ConditionalOnMissingBean` on every default

Every auto-configured bean is registered with `@ConditionalOnMissingBean`. This means that any developer can replace any internal component by simply declaring their own `@Bean` of the same type in their application context. There is no need to fork the library or extend internal classes.

### 2. Classpath isolation

`ExternalProviderAutoConfiguration` is guarded by `@ConditionalOnClass(BearerTokenAuthenticationFilter.class)`. This prevents `ClassNotFoundException` at startup when `spring-boot-starter-oauth2-resource-server` is not on the classpath (which it won't be for INTERNAL mode users).

`RedisRefreshTokenAutoConfiguration` is similarly guarded by `@ConditionalOnClass` for `StringRedisTemplate`.

### 3. Fail-fast validation

The library validates configuration at startup time and throws an `IllegalStateException` with a human-readable message if required properties are missing or incompatible. Examples:
- `security.auth-mode=OAUTH2` without `issuer-uri` or `jwk-set-uri`
- `security.refresh.store-mode=REDIS` without the Redis starter on the classpath
- `security.jwt.secret` missing in INTERNAL mode

### 4. Adapter pattern for authentication sources

`SecurityContextFilter` delegates to a priority-ordered list of `AuthenticationAdapter` implementations. This allows different authentication sources (INTERNAL JWT, Spring Security basic auth, OAuth2 JWT, Keycloak JWT) to all produce the same `AuthenticatedUser` model that the rest of the library works against.

---

## Filter Chain Architecture

### INTERNAL Mode

```
HTTP Request
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  JwtAuthenticationFilter  (OncePerRequestFilter)        │
│  • Reads Authorization: Bearer <token>                  │
│  • Calls JwtService.verifyToken(token)                  │
│  • On success: sets JwtAuthenticationToken in           │
│    SecurityContextHolder                                │
│  • On failure: clears SecurityContextHolder             │
└─────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  SecurityContextFilter  (OncePerRequestFilter)          │
│  • Reads Authentication from SecurityContextHolder      │
│  • Finds matching AuthenticationAdapter (by priority)   │
│  • Converts to AuthenticatedUser                        │
│  • Stores in SecurityUserContext (ThreadLocal)          │
│  • Clears ThreadLocal in finally block                  │
└─────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  Spring Security authorization                          │
│  (anyRequest().authenticated())                         │
└─────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  Controller Method                                      │
│  AuthorizationAspect intercepts @RequireRole /          │
│  @RequirePermission / @RequireOwner                     │
└─────────────────────────────────────────────────────────┘
```

### OAUTH2 / KEYCLOAK Mode

```
HTTP Request
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  BearerTokenAuthenticationFilter  (Spring OAuth2)       │
│  • Validates JWT against JWKS from issuer-uri           │
│  • Sets JwtAuthenticationToken in SecurityContextHolder │
└─────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  SecurityContextFilter  (same as above)                 │
│  Uses OAuth2AuthenticationAdapter or                    │
│  KeycloakAuthenticationAdapter                          │
└─────────────────────────────────────────────────────────┘
```

---

## Authentication Adapter Priority

| Adapter | `getOrder()` | Handles |
|---|---|---|
| `KeycloakAuthenticationAdapter` | 5 | `JwtAuthenticationToken` in KEYCLOAK mode |
| `OAuth2AuthenticationAdapter` | 10 | `JwtAuthenticationToken` in OAUTH2 mode |
| `JwtAuthenticationAdapter` | 50 | `JwtAuthenticationToken` from internal JWT |
| `SpringSecurityAuthenticationAdapter` | 100 | `UsernamePasswordAuthenticationToken` (fallback) |

`SecurityContextFilter` sorts adapters by `getOrder()` ascending and uses the first one that returns `supports(authentication) == true`.

---

## Observability Architecture

```
Any Security Transition (login, refresh, 401, 403, replay)
    │
    ▼
SecurityEventRecorder.record(type, outcome, userId, username, details)
    │
    ├─► SecurityAuditSink.publish(SecurityAuditEvent)
    │      Default: JsonSecurityAuditSink → SLF4J structured JSON
    │      Override: Kafka, SIEM, Splunk, any custom sink
    │
    └─► SecurityMetricsRecorder.increment(type, outcome)
           If Micrometer present: MicrometerSecurityMetricsRecorder
           If absent: NoOpSecurityMetricsRecorder (no failure)
```

MDC enrichment: `SecurityEventRecorder` automatically reads `traceId` and `requestId` from SLF4J MDC and includes them in every `SecurityAuditEvent.details` map.

---

## Auto-Configuration Registration

Three `@AutoConfiguration` classes are registered in:
`META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`

| Class | Condition | Purpose |
|---|---|---|
| `SecurityAutoConfiguration` | Always active | Core beans, INTERNAL mode filter chain |
| `RedisRefreshTokenAutoConfiguration` | `store-mode=REDIS` + Redis on classpath | Redis `RefreshTokenStore` |
| `ExternalProviderAutoConfiguration` | OAuth2 resource server on classpath | OAUTH2/KEYCLOAK filter chains and adapters |
