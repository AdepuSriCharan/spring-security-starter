<div align="center">

# 🔐 Spring Security Explainer

**A zero-configuration Spring Boot security starter for production-grade JWT authentication, role & permission authorization, and refresh-token rotation.**

[![Maven Central](https://img.shields.io/maven-central/v/io.github.adepusricharan/security-starter.svg?label=Maven%20Central&color=blue)](https://central.sonatype.com/artifact/io.github.adepusricharan/security-starter)
[![Java CI](https://github.com/AdepuSriCharan/spring-security-starter/actions/workflows/maven.yml/badge.svg)](https://github.com/AdepuSriCharan/spring-security-starter/actions/workflows/maven.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Java](https://img.shields.io/badge/Java-21+-brightgreen.svg)](https://www.oracle.com/java/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-4.x-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![GitHub Issues](https://img.shields.io/github/issues/AdepuSriCharan/spring-security-starter)](https://github.com/AdepuSriCharan/spring-security-starter/issues)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

<br/>

> **Stop writing boilerplate security code.** Add one dependency, implement one interface, and get enterprise-grade JWT security — with built-in support for INTERNAL self-managed JWTs, OAuth2, and Keycloak — fully wired, fully overridable.

<br/>

[📖 Documentation](#-quick-start) · [🐛 Report a Bug](https://github.com/AdepuSriCharan/spring-security-starter/issues) · [💡 Request a Feature](https://github.com/AdepuSriCharan/spring-security-starter/issues) · [🤝 Contributing](#-contributing)

</div>

---

## 📋 Table of Contents

- [Why Spring Security Explainer?](#-why-spring-security-explainer)
- [Feature Overview](#-feature-overview)
- [Architecture](#-architecture)
- [Module Structure](#-module-structure)
- [Quick Start](#-quick-start)
- [Authentication Modes](#-authentication-modes)
- [Built-in Endpoints](#-built-in-endpoints-internal-mode)
- [Authorization Annotations](#-authorization-annotations)
- [Refresh Token Rotation](#-refresh-token-rotation)
- [Observability](#-observability)
- [Overriding Defaults](#-overriding-defaults)
- [SecurityUserContext](#-securityusercontext)
- [Error Responses](#-error-responses)
- [Configuration Reference](#-configuration-reference)
- [Security Best Practices](#-security-best-practices)
- [Contributing](#-contributing)
- [Changelog](#-changelog)
- [License](#-license)

---

## 🚀 Why Spring Security Explainer?

Setting up Spring Security from scratch is notoriously complex — filter chains, JWT wiring, token rotation logic, exception handlers, and more. Most teams end up copying boilerplate across projects or missing critical security details like replay-attack detection.

**Spring Security Explainer eliminates all of that.**

| Without this library | With this library |
|---|---|
| Write `SecurityFilterChain` config | Zero config needed |
| Implement JWT filter from scratch | Auto-configured |
| Build token rotation logic manually | Built-in with replay detection |
| Wire OAuth2 / Keycloak extractors | First-class support |
| Add audit logging and metrics | Out of the box |
| Hook into auth context in services | `SecurityUserContext` ready |

---

## ✨ Feature Overview

### Authentication

- **Three auth modes**: `INTERNAL` (self-managed JWT), `OAUTH2` (generic OIDC), `KEYCLOAK` (Keycloak-specific extraction)
- Built-in `/login`, `/refresh`, `/logout` endpoints (INTERNAL mode)
- Access + Refresh JWT token lifecycle with configurable TTLs
- Refresh token rotation with **replay-attack detection**
- **Redis-backed** scalable refresh-token store (opt-in)

### Authorization

- `@RequireRole("ADMIN")` — role-based access control
- `@RequirePermission("post:delete")` — fine-grained permission checks
- `@RequireOwner("#userId")` — SpEL-based ownership enforcement (no service-layer check needed)
- Structured JSON 401 / 403 error responses

### Observability

- Security audit events (`LOGIN_SUCCESS`, `REFRESH_SUCCESS`, `ACCESS_DENIED`, etc.)
- Structured JSON audit logs via `SecurityAuditSink`
- Micrometer metrics: `security.audit.events`, `security.auth.refresh.latency`
- Fully configurable — disable via `security.security-events.enabled=false`

### Extensibility

- `@ConditionalOnMissingBean` on **every** default bean — override anything
- Pluggable `UserAccountProvider` — wire any data source
- Pluggable `RefreshTokenStore` — swap in-memory for JPA, Redis, or any backend
- Pluggable `SecurityAuditSink` — route events to Kafka, SIEM, or your own system

---

## 🏗 Architecture

```
HTTP Request
     │
     ▼
┌─────────────────────────────────────────────────────────┐
│  JwtAuthenticationFilter          (INTERNAL mode)       │
│  BearerTokenAuthenticationFilter  (OAUTH2 / KEYCLOAK)   │
└─────────────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────────┐
│  SecurityContextFilter                                  │
│  └─ Populates AuthenticatedUser into ThreadLocal        │
└─────────────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────────┐
│  Controller                                             │
│  └─ @RequireRole / @RequirePermission / @RequireOwner   │
└─────────────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────────┐
│  AuthorizationAspect  →  AuthorizationManager           │
│  └─ Validates roles / permissions / ownership           │
└─────────────────────────────────────────────────────────┘
     │
     ▼
  Allow  OR  SecurityAuthorizationException (→ 403)
```

**Observability pipeline** (parallel to every auth event):

```
Auth Event  →  SecurityAuditEventRecorder  →  SecurityAuditSink (JSON log / custom)
                                          →  Micrometer Metrics (counters / timers)
```

---

## 📦 Module Structure

```
spring-security-explainer/
│
├── security-core/              # Public API — interfaces, annotations, enums
│   ├── UserAccount             # Implement to load users from your data source
│   ├── UserAccountProvider     # SPI for user lookup
│   ├── AuthenticatedUser       # Thread-local security context model
│   ├── AuthMode                # INTERNAL | OAUTH2 | KEYCLOAK
│   ├── @RequireRole            # Role-based authorization annotation
│   ├── @RequirePermission      # Permission-based authorization annotation
│   └── @RequireOwner           # SpEL ownership authorization annotation
│
├── security-autoconfigure/     # Spring Boot auto-configuration
│   ├── JwtAuthenticationFilter
│   ├── SecurityContextFilter
│   ├── AuthorizationAspect
│   ├── AuthorizationManager
│   ├── RefreshTokenStore       # In-memory (default) | Redis (opt-in)
│   ├── SecurityAuditSink       # Structured JSON logger (default)
│   └── SecurityProperties      # All `security.*` config binding
│
├── security-starter/           # Single dependency — imports everything
│
├── security-test/              # Test utilities and integration helpers
│
└── testing-security-explainer/ # Demo application (INTERNAL / KEYCLOAK / OAUTH2)
    └── logs/                   # Reproducible observability evidence pack
```

---

## ⚡ Quick Start

### 1. Add Dependency

```xml
<dependency>
    <groupId>io.github.adepusricharan</groupId>
    <artifactId>security-starter</artifactId>
    <version>1.2.0</version>
</dependency>
```

> For **OAuth2 / Keycloak** mode, also add the resource server dependency:
>
> ```xml
> <dependency>
>     <groupId>org.springframework.boot</groupId>
>     <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
> </dependency>
> ```

### 2. Configure

```properties
# application.properties
security.auth-mode=INTERNAL
security.jwt.secret=${JWT_SECRET}          # min 32 characters
security.jwt.expiration-ms=3600000         # 1 hour
security.jwt.refresh-expiration-ms=604800000  # 7 days
security.jwt.issuer=my-application
```

### 3. Implement `UserAccountProvider`

```java
@Service
public class JpaUserAccountProvider implements UserAccountProvider {

    private final UserRepository repository;

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

**That's it.** No filters. No JWT wiring. No `SecurityFilterChain`. Your application is now secured.

---

## 🔑 Authentication Modes

### `INTERNAL` (default)

Self-managed JWT. You own the users, passwords, and token lifecycle. Ideal for applications managing their own user database.

```properties
security.auth-mode=INTERNAL
security.jwt.secret=${JWT_SECRET}
security.jwt.expiration-ms=3600000
security.jwt.refresh-expiration-ms=604800000
security.jwt.issuer=my-application
```

**Flow:** `POST /login` → access token + refresh token → `POST /refresh` to rotate → `POST /logout` to revoke.

---

### `KEYCLOAK`

Deep Keycloak JWT extraction. Automatically maps realm roles → `roles` and client roles → `permissions`.

```properties
security.auth-mode=KEYCLOAK
security.oauth2.issuer-uri=http://localhost:8080/realms/my-realm
security.oauth2.keycloak-client-id=my-client
```

Optionally customize claim extraction:

```properties
security.oauth2.claims.username-claim=preferred_username
security.oauth2.claims.user-id-claim=sub
```

---

### `OAUTH2`

Generic OIDC/OAuth2 provider with flat JWT claim extraction. Works with Google, Auth0, Okta, and any standards-compliant provider.

```properties
security.auth-mode=OAUTH2
security.oauth2.issuer-uri=https://accounts.google.com
security.oauth2.claims.username-claim=email
security.oauth2.claims.user-id-claim=sub
security.oauth2.claims.roles-claim=roles
security.oauth2.claims.permissions-claim=permissions
```

---

### `Google Sign-In` (Hybrid)

Use this when you want both internal username/password users and Google users in the same app.

The app keeps `security.auth-mode=INTERNAL` as the source of truth for sessions, refresh tokens, logout, and authorization. Google is only used as the identity proof step, then the backend issues the normal internal JWT pair.

```properties
security.auth-mode=INTERNAL
security.google.enabled=true
security.google.issuer-uri=https://accounts.google.com
security.google.client-id=YOUR_GOOGLE_CLIENT_ID
security.google.auto-link-by-email=true
```

Client flow:

1. Get a Google `idToken` on the web or mobile client.
2. `POST /login/google` with that token.
3. Use the returned `accessToken` and `refreshToken` like any other login.
4. Call `/refresh` and `/logout` with the internal refresh token.

This works well for:

- browser apps
- React Native / Expo apps
- mixed teams that want both local accounts and Google sign-in

## 🌐 Built-in Endpoints (INTERNAL mode)

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `POST` | `/login` | Authenticate → access + refresh tokens | ❌ Public |
| `POST` | `/refresh` | Rotate refresh token → new token pair | ❌ Public |
| `POST` | `/logout` | Revoke refresh token | ❌ Public |

**Login request:**

```json
{
  "username": "john.doe",
  "password": "secret123"
}
```

**Login response:**

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiJ9...",
  "tokenType": "Bearer",
  "expiresIn": 3600000
}
```

---

## 🛡 Authorization Annotations

Annotations are applied at the controller method level and enforced via AOP — no service-layer code needed.

```java
// Role-based: single role
@GetMapping("/admin/dashboard")
@RequireRole("ADMIN")
public String adminDashboard() { ... }

// Role-based: any of multiple roles
@GetMapping("/reports")
@RequireRole({"ADMIN", "MANAGER"})
public String reports() { ... }

// Permission-based
@DeleteMapping("/posts/{id}")
@RequirePermission("post:delete")
public void deletePost(@PathVariable String id) { ... }

// Ownership: SpEL expression matched against authenticated user ID
@GetMapping("/users/{userId}/profile")
@RequireOwner("#userId")
public UserProfile getProfile(@PathVariable String userId) { ... }

// Ownership with nested expression
@PutMapping("/orders/{orderId}")
@RequireOwner("#request.customerId")
public Order updateOrder(@PathVariable String orderId,
                         @RequestBody UpdateOrderRequest request) { ... }
```

> **`@RequireOwner`** uses SpEL to extract the owner ID from method arguments and compares it against the authenticated user's ID — no database lookup required.

### Public Endpoints

```properties
# Comma-separated Ant patterns
security.public-endpoints=/register,/health,/actuator/**,/api/v1/public/**
```

`/login`, `/refresh`, and `/logout` are always public in INTERNAL mode.

---

## 🔄 Refresh Token Rotation

Every `POST /refresh` call performs atomic token rotation:

1. **Verify** — validate the presented refresh token
2. **Revoke** — mark the old refresh token as consumed
3. **Issue** — generate a new access token + refresh token pair
4. **Store** — persist only the new token's SHA-256 hash

### Replay-Attack Detection

If a **previously revoked** refresh token is reused:
- All refresh tokens for that user are **immediately revoked**
- Forces re-authentication, containing any token theft scenario

### Refresh Token Store Options

| Mode | Config | Best For |
|------|--------|----------|
| In-Memory (default) | `security.refresh.store-mode=INMEMORY` | Single-instance, development |
| Redis | `security.refresh.store-mode=REDIS` | Multi-instance, production |
| Custom | Implement `RefreshTokenStore` | Any backend (JPA, DynamoDB, etc.) |

**Redis configuration:**

```properties
security.refresh.store-mode=REDIS
security.refresh.redis.key-prefix=security:refresh

# Standard Spring Redis properties
spring.data.redis.host=localhost
spring.data.redis.port=6379
```

> ⚠️ If `store-mode=REDIS` is set without Redis on the classpath, the application **fails fast** with a clear error message on startup.

**Verify Redis integration:**

```bash
# 1. Login to generate a refresh token, then hash it:
echo -n '<REFRESH_TOKEN>' | sha256sum

# 2. Confirm token stored in Redis:
redis-cli --scan --pattern 'security:refresh:*'
# Expected keys:
#   security:refresh:token:<sha256>
#   security:refresh:user:<userId>:tokens

# 3. After /refresh call, old key remains (marked revoked), new key appears
```

**Custom store example:**

```java
@Service
public class JpaRefreshTokenStore implements RefreshTokenStore {

    @Override
    public void store(RefreshTokenEntry entry) { /* persist to DB */ }

    @Override
    public Optional<RefreshTokenEntry> consume(String tokenHash) { /* atomic revoke + return */ }

    @Override
    public void revokeAll(String userId) { /* revoke all user tokens */ }
}
```

Spring Boot replaces the default automatically when your `@Bean` is present.

---

## 📊 Observability

### Security Audit Events

All security transitions emit structured `SecurityAuditEvent` records:

| Event Type | Trigger |
|---|---|
| `LOGIN_SUCCESS` | Successful authentication |
| `LOGIN_FAILURE` | Invalid credentials |
| `REFRESH_SUCCESS` | Successful token rotation |
| `REFRESH_FAILURE` | Invalid or expired refresh token |
| `LOGOUT` | Token revocation |
| `ACCESS_DENIED` | Authorization check failed (403) |
| `UNAUTHORIZED` | Missing or invalid token (401) |
| `REPLAY_ATTACK_DETECTED` | Reuse of revoked refresh token |

**Default output** (JSON structured log):

```json
{
  "eventType": "LOGIN_SUCCESS",
  "userId": "user-123",
  "username": "john.doe",
  "ipAddress": "192.168.1.1",
  "timestamp": "2026-01-15T10:30:00Z",
  "metadata": {}
}
```

**Custom audit sink** — route events anywhere:

```java
@Service
public class KafkaAuditSink implements SecurityAuditSink {

    @Override
    public void record(SecurityAuditEvent event) {
        kafkaTemplate.send("security-audit-events", event);
    }
}
```

### Micrometer Metrics

| Metric | Type | Tags |
|---|---|---|
| `security.audit.events` | Counter | `eventType`, `authMode` |
| `security.auth.refresh.latency` | Timer | `outcome` |

> Micrometer is **truly optional** — the starter starts without any failure if Micrometer is absent from the classpath.

**Disable all audit events:**

```properties
security.security-events.enabled=false
```

### Demo Observability Evidence Pack

The demo application includes a reproducible log pack:

```
testing-security-explainer/logs/
├── README.md                     # Guided interpretation
├── http-cases-summary.txt        # Expected HTTP outcomes per scenario
├── security-audit-events.txt     # Full structured audit event output
└── cases/
    ├── *.code                    # curl / httpie commands
    └── *.json                    # Response payloads
```

Regenerate all artifacts:

```bash
bash testing-security-explainer/logs/reproduce.sh
```

---

## 🔧 Overriding Defaults

All components are registered with `@ConditionalOnMissingBean`. Declare your own `@Bean` to replace any default:

| Bean Interface / Class | Default Implementation | Override Use Case |
|---|---|---|
| `UserAccountProvider` | *(must implement)* | Wire your user repository |
| `AuthorizationManager` | `DefaultAuthorizationManager` | Custom role/permission logic |
| `RefreshTokenStore` | `InMemoryRefreshTokenStore` | JPA, Redis, or any persistence |
| `PasswordEncoder` | `BCryptPasswordEncoder` | Argon2, SCrypt, etc. |
| `SecurityFilterChain` | Stateless JWT chain | Full custom filter chain |
| `AuthenticationAdapter` | JWT + Spring Security adapters | Custom token validation |
| `SecurityContextFilter` | ThreadLocal propagation filter | Custom context propagation |
| `SecurityAuditSink` | JSON structured logger | Kafka, SIEM, Splunk, etc. |

**Example — custom password encoder:**

```java
@Configuration
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new Argon2PasswordEncoder(16, 32, 1, 65536, 10);
    }
}
```

---

## 👤 SecurityUserContext

Access the authenticated user anywhere within the request thread:

```java
// Returns null if no authenticated user in context
AuthenticatedUser user = SecurityUserContext.getCurrentUser();

// Throws SecurityException if no authenticated user
AuthenticatedUser user = SecurityUserContext.requireCurrentUser();

// Usage in service layer
@Service
public class OrderService {

    public Order createOrder(CreateOrderRequest request) {
        AuthenticatedUser currentUser = SecurityUserContext.requireCurrentUser();
        // Use currentUser.getId(), currentUser.getRoles(), etc.
    }
}
```

> ⚠️ **ThreadLocal-based** — not propagated to `@Async` threads, schedulers, or Kafka listeners. For async contexts, capture the user before crossing thread boundaries.

---

## ⚠️ Error Responses

All error responses are structured JSON — no HTML error pages, no stack trace leakage.

**401 Unauthenticated** — missing or invalid token:

```json
{
  "error": "UNAUTHORIZED",
  "message": "Authentication required to access this resource",
  "timestamp": "2026-03-01T14:00:00Z"
}
```

**403 Forbidden** — authenticated but insufficient privileges:

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

**403 Forbidden** — ownership violation:

```json
{
  "error": "FORBIDDEN",
  "type": "OWNERSHIP",
  "message": "Access denied. Resource does not belong to the authenticated user.",
  "timestamp": "2026-03-01T14:00:00Z"
}
```

---

## ⚙️ Configuration Reference

### Core

| Property | Default | Description |
|---|---|---|
| `security.auth-mode` | `INTERNAL` | Authentication mode: `INTERNAL`, `OAUTH2`, `KEYCLOAK` |
| `security.public-endpoints` | — | Comma-separated Ant patterns for public endpoints |
| `security.security-events.enabled` | `true` | Enable/disable security audit event publishing |

### JWT (INTERNAL mode)

| Property | Default | Description |
|---|---|---|
| `security.jwt.secret` | — | **Required.** HS256 signing secret. Minimum 32 characters. |
| `security.jwt.expiration-ms` | `3600000` | Access token TTL in milliseconds (default: 1 hour) |
| `security.jwt.refresh-expiration-ms` | `604800000` | Refresh token TTL in milliseconds (default: 7 days) |
| `security.jwt.issuer` | — | JWT `iss` claim value |

### Refresh Token Store

| Property | Default | Description |
|---|---|---|
| `security.refresh.store-mode` | `INMEMORY` | Refresh token backend: `INMEMORY` or `REDIS` |
| `security.refresh.redis.key-prefix` | `security:refresh` | Redis key namespace prefix |

### OAuth2 / Keycloak

| Property | Default | Description |
|---|---|---|
| `security.oauth2.issuer-uri` | — | Required for `OAUTH2` / `KEYCLOAK`. OIDC discovery endpoint. |
| `security.oauth2.jwk-set-uri` | — | Alternative to `issuer-uri` for JWK Set endpoint |
| `security.oauth2.keycloak-client-id` | — | Required for `KEYCLOAK` client role extraction |
| `security.oauth2.claims.username-claim` | `preferred_username` | JWT claim mapped to username |
| `security.oauth2.claims.user-id-claim` | `sub` | JWT claim mapped to user ID |
| `security.oauth2.claims.roles-claim` | `roles` | JWT claim for roles (`OAUTH2` flat mode) |
| `security.oauth2.claims.permissions-claim` | `permissions` | JWT claim for permissions (`OAUTH2` flat mode) |

---

## 🔒 Security Best Practices

Following these practices is strongly recommended for production deployments:

- **Use a strong secret** — generate a cryptographically random 256-bit (32 byte) secret for INTERNAL mode:
  ```bash
  openssl rand -base64 32
  ```
- **Never commit secrets** — use environment variables or a secrets manager (AWS Secrets Manager, Vault, etc.)
- **Always use HTTPS** — JWT tokens must be transmitted over TLS only
- **Keep access tokens short-lived** — 15–60 minutes is recommended; default is 1 hour
- **Use Redis in production** — replace `InMemoryRefreshTokenStore` for all clustered / multi-instance deployments
- **Monitor audit events** — wire `SecurityAuditSink` to your SIEM or alerting system
- **Enable replay detection logging** — `REPLAY_ATTACK_DETECTED` events indicate potential token theft

---

## 🤝 Contributing

Contributions are welcome and greatly appreciated! Here's how to get started:

### Development Setup

```bash
# Clone the repository
git clone https://github.com/AdepuSriCharan/spring-security-starter.git
cd spring-security-starter

# Build all modules
./mvnw clean install -DskipTests

# Run tests
./mvnw test
```

### Guidelines

- **Fork → Feature Branch → Pull Request** workflow
- Follow the coding standards documented in [`PLAN.md`](PLAN.md) (AI Coding Standards section)
- All PRs must include tests for new behavior
- Minimum coverage target: **70–80%** on service and core layers
- Write clear, descriptive commit messages

### Issue Reporting

Please use [GitHub Issues](https://github.com/AdepuSriCharan/spring-security-starter/issues) with:
- Clear description of the problem or feature request
- Steps to reproduce (for bugs)
- Relevant configuration and environment details
- Spring Boot and Java version

---

## 📅 Changelog

### v1.1.2 — Observability Stabilization

- Security audit event system (`SecurityAuditEvent`, `SecurityAuditSink`, `SecurityAuditEventType`)
- Default structured JSON audit logger
- Micrometer metrics: `security.audit.events`, `security.auth.refresh.latency`
- `security.security-events.enabled` config toggle
- **Runtime fix**: Micrometer is now truly optional — no startup failure when absent
- Audit events emitted for: login, refresh, logout, 401, 403, replay detection
- Demo observability evidence pack with reproducible log artifacts

### v1.2.0 — Hybrid Google Sign-In + Session Management

- Google sign-in exchange at `POST /login/google`
- Interactive Google auth lab at `/google-auth-lab`
- Internal user linking for Google identities
- Session management API for listing and revoking active sessions
- Audit events for Google auth and session-admin actions
- Demo app updated to exercise the new hybrid flow end to end

### v1.1.1 — Redis Refresh Token Store

- `security.refresh.store-mode=INMEMORY|REDIS`
- Redis-backed `RefreshTokenStore` with token hash storage, user token index, TTL expiry
- Atomic consume-for-rotation path
- Replay detection and revoke-all handling
- Redis-focused test suite (rotation, replay, revoke, concurrency, TTL)

### v1.1.0 — Core Authorization

- `@RequireRole`, `@RequirePermission`, `@RequireOwner` annotations
- SpEL-based ownership evaluation
- Structured JSON 401 / 403 error responses
- `SecurityUserContext` ThreadLocal context accessor

### v1.0.0 — Initial Release

- INTERNAL mode: JWT access + refresh token lifecycle
- Built-in `/login`, `/refresh`, `/logout` endpoints
- OAUTH2 and KEYCLOAK auth modes
- `UserAccountProvider` SPI
- `@ConditionalOnMissingBean` on all defaults

> **Roadmap (next):** Login rate limiting, account lockout, and observability expansion. See [`PLAN.md`](PLAN.md) for full details.

---

## 📄 License

This project is licensed under the **Apache License, Version 2.0**.

```
Copyright 2024 Adepu Sri Charan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

<div align="center">

**Built with ❤️ for the Spring Boot community**

[⭐ Star this project](https://github.com/AdepuSriCharan/spring-security-starter) · [🐛 Report a Bug](https://github.com/AdepuSriCharan/spring-security-starter/issues) · [💡 Request a Feature](https://github.com/AdepuSriCharan/spring-security-starter/issues)

</div>
