# Configuration Reference

Complete reference for all `security.*` configuration properties.

---

## Core Properties

| Property | Type | Default | Description |
|---|---|---|---|
| `security.auth-mode` | `AuthMode` | `INTERNAL` | Authentication mode. One of `INTERNAL`, `OAUTH2`, `KEYCLOAK`. |
| `security.public-endpoints` | `List<String>` | `[]` | Ant-pattern paths that require no authentication. |
| `security.security-events.enabled` | `boolean` | `true` | Enable or disable all security audit event publishing. |

### Auth Mode Summary

| Mode | What it does |
|---|---|
| `INTERNAL` | Self-managed JWT. The starter owns the full authentication lifecycle. Requires `security.jwt.secret`. |
| `OAUTH2` | JWT resource server mode. Delegates token validation to Spring's `BearerTokenAuthenticationFilter`. Requires `spring.security.oauth2.resourceserver.jwt.issuer-uri` or `jwk-set-uri`. |
| `KEYCLOAK` | Like `OAUTH2` but adds automatic extraction of Keycloak's nested `realm_access.roles` and `resource_access.<client>.roles` claim structures. |

---

## JWT Properties (INTERNAL Mode Only)

> These properties are only used when `security.auth-mode=INTERNAL`. They are silently ignored in OAUTH2 and KEYCLOAK modes.

| Property | Type | Default | Description |
|---|---|---|---|
| `security.jwt.secret` | `String` | **required** | HMAC-SHA256 signing secret. Minimum 32 characters. Use `openssl rand -base64 32` to generate. |
| `security.jwt.expiration-ms` | `long` | `3600000` | Access token TTL in milliseconds. Default: 1 hour. |
| `security.jwt.refresh-expiration-ms` | `long` | `604800000` | Refresh token TTL in milliseconds. Default: 7 days. |
| `security.jwt.issuer` | `String` | `spring-security-explainer` | Value of the JWT `iss` claim. |

**Example:**
```properties
security.jwt.secret=${JWT_SECRET}
security.jwt.expiration-ms=900000       # 15 minutes
security.jwt.refresh-expiration-ms=2592000000  # 30 days
security.jwt.issuer=my-api
```

---

## Refresh Token Store Properties

| Property | Type | Default | Description |
|---|---|---|---|
| `security.refresh.store-mode` | `RefreshStoreMode` | `INMEMORY` | Backend for refresh token storage. `INMEMORY` or `REDIS`. |
| `security.refresh.redis.key-prefix` | `String` | `security:refresh` | Redis key namespace prefix. |

### Store Mode Comparison

| Mode | Suitable For | Notes |
|---|---|---|
| `INMEMORY` | Development, single-instance deployments | Lost on restart. Not safe for horizontal scaling. |
| `REDIS` | Production, multi-instance deployments | Requires `spring-boot-starter-data-redis` on the classpath and a running Redis server. Application fails fast on startup if Redis is unreachable. |
| Custom | Any backend (JPA, DynamoDB, Cassandra) | Implement `RefreshTokenStore` and declare it as a `@Bean`. |

**Redis example:**
```properties
security.refresh.store-mode=REDIS
security.refresh.redis.key-prefix=myapp:security:refresh
spring.data.redis.host=redis.internal
spring.data.redis.port=6379
```

---

## OAuth2 Claim Mapping (OAUTH2 Mode)

> Used when `security.auth-mode=OAUTH2`.

| Property | Type | Default | Description |
|---|---|---|---|
| `security.oauth2.username-claim` | `String` | `preferred_username` | JWT claim mapped to `AuthenticatedUser.getUsername()`. |
| `security.oauth2.user-id-claim` | `String` | `sub` | JWT claim mapped to `AuthenticatedUser.getUserId()`. |
| `security.oauth2.roles-claim` | `String` | `roles` | JWT claim (array) mapped to `AuthenticatedUser.getRoles()`. |
| `security.oauth2.permissions-claim` | `String` | `permissions` | JWT claim (array) mapped to `AuthenticatedUser.getPermissions()`. |

**Example (Auth0):**
```properties
security.auth-mode=OAUTH2
spring.security.oauth2.resourceserver.jwt.issuer-uri=https://my-tenant.auth0.com/
security.oauth2.username-claim=email
security.oauth2.user-id-claim=sub
security.oauth2.roles-claim=https://myapp.com/roles
security.oauth2.permissions-claim=https://myapp.com/permissions
```

---

## Keycloak Claim Mapping (KEYCLOAK Mode)

> Used when `security.auth-mode=KEYCLOAK`.

| Property | Type | Default | Description |
|---|---|---|---|
| `security.keycloak.realm-access-claim` | `String` | `realm_access` | Top-level claim containing realm-level roles. |
| `security.keycloak.client-id` | `String` | `""` | Your Keycloak client ID. Required to extract `resource_access.<clientId>.roles`. Leave blank to skip client role extraction. |
| `security.keycloak.resource-access-claim` | `String` | `resource_access` | Top-level claim containing per-client roles. |
| `security.keycloak.roles-key` | `String` | `roles` | The inner key in `realm_access` and `resource_access.<client>` that holds the roles array. |

**Example:**
```properties
security.auth-mode=KEYCLOAK
spring.security.oauth2.resourceserver.jwt.issuer-uri=http://localhost:9090/realms/my-realm
security.keycloak.client-id=my-spring-app
security.keycloak.realm-access-claim=realm_access
security.keycloak.resource-access-claim=resource_access
security.keycloak.roles-key=roles
```

---

## Spring-standard Properties Used

These are standard Spring properties consumed by the starter:

| Property | Used When |
|---|---|
| `spring.security.oauth2.resourceserver.jwt.issuer-uri` | `OAUTH2` / `KEYCLOAK` mode — OIDC discovery |
| `spring.security.oauth2.resourceserver.jwt.jwk-set-uri` | `OAUTH2` / `KEYCLOAK` mode — direct JWKS URL |
| `spring.data.redis.host` | `security.refresh.store-mode=REDIS` |
| `spring.data.redis.port` | `security.refresh.store-mode=REDIS` |

---

## Fail-Fast Validation

The starter performs the following checks at application startup and throws `IllegalStateException` with a clear message if any check fails:

| Condition | Error |
|---|---|
| `auth-mode=OAUTH2` or `KEYCLOAK` without `issuer-uri` or `jwk-set-uri` | `security.auth-mode=OAUTH2 requires either spring.security.oauth2.resourceserver.jwt.issuer-uri or jwk-set-uri` |
| `refresh.store-mode=REDIS` without the Redis starter on the classpath | `security.refresh.store-mode=REDIS requires Redis support on the classpath` |
| `auth-mode=INTERNAL` with no `jwt.secret` configured | `JWT secret is not configured. Set 'security.jwt.secret'` |
| `store-mode=REDIS` but Redis is not reachable | `Redis is not reachable. Check spring.data.redis.host/port` |

---

## Minimal Configuration Examples

### INTERNAL (default)
```properties
security.auth-mode=INTERNAL
security.jwt.secret=${JWT_SECRET}
```

### OAUTH2
```properties
security.auth-mode=OAUTH2
spring.security.oauth2.resourceserver.jwt.issuer-uri=https://accounts.google.com
security.oauth2.username-claim=email
```

### KEYCLOAK
```properties
security.auth-mode=KEYCLOAK
spring.security.oauth2.resourceserver.jwt.issuer-uri=http://localhost:9090/realms/demo
security.keycloak.client-id=my-app
```

### INTERNAL + Redis
```properties
security.auth-mode=INTERNAL
security.jwt.secret=${JWT_SECRET}
security.refresh.store-mode=REDIS
spring.data.redis.host=localhost
spring.data.redis.port=6379
```
