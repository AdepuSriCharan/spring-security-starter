# Spring Security Explainer

[![Maven Central](https://img.shields.io/maven-central/v/io.github.adepusricharan/security-starter.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/io.github.adepusricharan/security-starter)
[![Java CI](https://github.com/AdepuSriCharan/spring-security-starter/actions/workflows/maven.yml/badge.svg)](https://github.com/AdepuSriCharan/spring-security-starter/actions/workflows/maven.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Java](https://img.shields.io/badge/Java-17+-green.svg)](https://www.oracle.com/java/)

A zero-configuration Spring Boot starter that provides **JWT authentication, role & permission authorization, ownership checks, and refresh-token rotation** — with built-in support for **INTERNAL, OAuth2, and Keycloak** authentication modes.

> Let developers focus on business logic instead of writing complex Spring Security configuration.

---

## Features

- **Three auth modes**: `INTERNAL` (self-managed JWT), `OAUTH2` (generic OIDC providers), `KEYCLOAK` (Keycloak-specific role/permission extraction)
- Access + Refresh JWT token lifecycle (INTERNAL mode)
- Built-in `/login`, `/refresh`, `/logout` endpoints (INTERNAL mode)
- Role-based authorization — `@RequireRole`
- Permission-based authorization — `@RequirePermission`
- Ownership authorization using SpEL — `@RequireOwner`
- Refresh token rotation with replay-attack detection
- Structured JSON error responses (401 & 403)
- `@ConditionalOnMissingBean` on all beans — fully overridable
- No `ClassNotFoundException` when `spring-boot-starter-oauth2-resource-server` is absent

---

## Modules

```
security-core/              → Interfaces, annotations, AuthMode enum
security-autoconfigure/     → Spring Boot auto-configuration
security-starter/           → Single dependency to import
security-test/              → Integration test helpers
testing-security-explainer/ → Demo app (INTERNAL / KEYCLOAK / OAUTH2)
```

---

# Quick Start

## 1. Add Dependency

```xml
<dependency>
    <groupId>io.github.adepusricharan</groupId>
    <artifactId>security-starter</artifactId>
    <version>1.1.0</version>
</dependency>
```

For **OAuth2 / Keycloak** mode also add:

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
```

---

# Auth Modes

### `INTERNAL` (default)

Self-managed JWT. You own the users, passwords, and token lifecycle.

```properties
security.auth-mode=INTERNAL
security.jwt.secret=${JWT_SECRET}
security.jwt.expiration-ms=3600000
security.jwt.refresh-expiration-ms=604800000
security.jwt.issuer=my-application
```

Implement `UserAccountProvider` to load users from your database:

```java
@Service
public class JpaUserAccountProvider implements UserAccountProvider {

    @Override
    public Optional<UserAccount> findByUsername(String username) {
        return repository.findByUsername(username)
                .map(user -> new UserAccount() {
                    public String getId()               { return user.getId(); }
                    public String getUsername()         { return user.getUsername(); }
                    public String getPassword()         { return user.getPassword(); }
                    public Set<String> getRoles()       { return user.getRoles(); }
                    public Set<String> getPermissions() { return user.getPermissions(); }
                });
    }
}
```

That's it. No filters. No security config. No JWT wiring.

---

### `KEYCLOAK`

Deep Keycloak JWT extraction. Realm roles → `roles`, client roles → `permissions`.

```properties
security.auth-mode=KEYCLOAK
security.oauth2.issuer-uri=http://localhost:8080/realms/my-realm
security.oauth2.keycloak-client-id=my-client
```

Optionally customise claim names:

```properties
security.oauth2.claims.username-claim=preferred_username
security.oauth2.claims.user-id-claim=sub
```

---

### `OAUTH2`

Generic OIDC / OAuth2 provider with flat JWT claim extraction.

```properties
security.auth-mode=OAUTH2
security.oauth2.issuer-uri=https://accounts.google.com
security.oauth2.claims.username-claim=email
security.oauth2.claims.user-id-claim=sub
security.oauth2.claims.roles-claim=roles
security.oauth2.claims.permissions-claim=permissions
```

---

## Built-in Endpoints (INTERNAL mode)

| Method | Path       | Description                             |
|--------|------------|-----------------------------------------|
| POST   | `/login`   | Authenticate → access + refresh tokens  |
| POST   | `/refresh` | Rotate refresh token → new token pair   |
| POST   | `/logout`  | Revoke refresh token                    |

---

# Authorization Annotations

```java
@GetMapping("/admin")
@RequireRole("ADMIN")
public String admin() { ... }

@GetMapping("/reports")
@RequireRole({"ADMIN", "MANAGER"})
public String reports() { ... }

@DeleteMapping("/posts/{id}")
@RequirePermission("post:delete")
public void delete(@PathVariable String id) { ... }

@GetMapping("/users/{userId}")
@RequireOwner("#userId")
public User profile(@PathVariable String userId) { ... }
```

`@RequireOwner` uses SpEL to extract the owner ID from method arguments and compares it against the authenticated user's ID — no service-layer check needed.

---

## Authorization Flow

```
HTTP Request
     ↓
JwtAuthenticationFilter  (INTERNAL) | BearerTokenAuthenticationFilter (OAUTH2/KEYCLOAK)
     ↓
SecurityContextFilter        ← populates AuthenticatedUser into ThreadLocal
     ↓
Controller
     ↓
AuthorizationAspect          ← intercepts @RequireRole / @RequirePermission / @RequireOwner
     ↓
AuthorizationManager         ← validates roles / permissions / ownership
     ↓
Allow  OR  SecurityAuthorizationException (→ 403)
```

---

# Public Endpoints

```properties
security.public-endpoints=/register,/health,/actuator/**
```

`/login`, `/refresh`, `/logout` are always public in INTERNAL mode.

---

# Error Responses

**401 Unauthenticated**

```json
{
  "error": "UNAUTHORIZED",
  "message": "Authentication required to access this resource",
  "timestamp": "2026-03-01T14:00:00Z"
}
```

**403 Forbidden**

```json
{
  "error": "FORBIDDEN",
  "type": "ROLE",
  "required": ["ADMIN"],
  "actual": ["USER"],
  "message": "Access denied for user 'john'. Required role: [ADMIN]. User has: [USER]",
  "timestamp": "2026-03-01T14:00:00Z"
}
```

---

# Refresh Token Rotation (INTERNAL mode)

Every `/refresh` call:
1. Old refresh token is revoked
2. New access + refresh token pair is issued
3. New refresh token hash stored

**Replay Detection**: if a revoked token is reused → all tokens for that user are immediately revoked.

**Custom store** — replace `InMemoryRefreshTokenStore` for production / clustered deployments:

```java
@Service
public class JpaRefreshTokenStore implements RefreshTokenStore {
    // persist tokens to database
}
```

Spring replaces the default automatically when your bean exists.

---

# Overriding Defaults

All components use `@ConditionalOnMissingBean`. Declare your own `@Bean` to override any of them:

| Bean                    | Default                          |
|-------------------------|----------------------------------|
| `AuthorizationManager`  | `DefaultAuthorizationManager`    |
| `RefreshTokenStore`     | `InMemoryRefreshTokenStore`      |
| `PasswordEncoder`       | `BCryptPasswordEncoder`          |
| `SecurityFilterChain`   | Stateless JWT chain              |
| `AuthenticationAdapter` | JWT + SpringSecurity adapters    |
| `SecurityContextFilter` | ThreadLocal propagation filter   |
| Exception Handlers      | Structured JSON responses        |

---

# SecurityUserContext

Access the authenticated user anywhere in the request thread:

```java
AuthenticatedUser user = SecurityUserContext.getCurrentUser();     // nullable
AuthenticatedUser user = SecurityUserContext.requireCurrentUser(); // throws if null
```

> ⚠ ThreadLocal-based — not available in `@Async` threads, schedulers, or Kafka listeners.

---

# Configuration Reference

| Property | Default | Description |
|---|---|---|
| `security.auth-mode` | `INTERNAL` | `INTERNAL`, `OAUTH2`, or `KEYCLOAK` |
| `security.jwt.secret` | — | **Required** for INTERNAL. Min 32 chars. |
| `security.jwt.expiration-ms` | `3600000` | Access token TTL (1 hour) |
| `security.jwt.refresh-expiration-ms` | `604800000` | Refresh token TTL (7 days) |
| `security.jwt.issuer` | — | JWT `iss` claim value |
| `security.public-endpoints` | — | Comma-separated public paths |
| `security.oauth2.issuer-uri` | — | Required for OAUTH2 / KEYCLOAK |
| `security.oauth2.jwk-set-uri` | — | Alternative to `issuer-uri` |
| `security.oauth2.keycloak-client-id` | — | Required for KEYCLOAK client role extraction |
| `security.oauth2.claims.username-claim` | `preferred_username` | JWT claim for username |
| `security.oauth2.claims.user-id-claim` | `sub` | JWT claim for user ID |
| `security.oauth2.claims.roles-claim` | `roles` | JWT claim for roles (OAUTH2 flat) |
| `security.oauth2.claims.permissions-claim` | `permissions` | JWT claim for permissions (OAUTH2 flat) |

---

# Recommended Practices

- Use a strong 256-bit secret for INTERNAL mode
- Store secrets in environment variables, never in source control
- Always use HTTPS in production
- Replace `InMemoryRefreshTokenStore` in clustered deployments
- Keep access token lifetime short (≤ 1 hour)

---

**You now have a pluggable, multi-mode application-level security layer for Spring Boot.**
