# Spring Security Explainer

[![Maven Central](https://img.shields.io/maven-central/v/io.github.adepusricharan/security-starter.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/io.github.adepusricharan/security-starter)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Java](https://img.shields.io/badge/Java-17+-green.svg)](https://www.oracle.com/java/)

A zero-configuration Spring Boot starter that provides **JWT authentication, role & permission authorization, ownership checks, and refresh-token rotation** out of the box.

The goal of this project is simple:

> Let developers focus on business logic instead of writing complex Spring Security configuration.

---

## Features

* Access + Refresh JWT authentication
* Automatic `/login`, `/refresh`, `/logout` endpoints
* Role-based authorization (`@RequireRole`)
* Permission-based authorization (`@RequirePermission`)
* Ownership authorization using SpEL (`@RequireOwner`)
* Refresh token rotation with replay-attack detection
* Structured JSON error responses (401 & 403)
* Fully overridable components using Spring Boot auto-configuration
* Works with DB login, JWT login, or external providers (Keycloak / OAuth later)

---

# Quick Start

## 1. Add Dependency

```xml
<dependency>
    <groupId>io.github.adepusricharan</groupId>
    <artifactId>security-starter</artifactId>
    <version>1.0.2</version>
</dependency>
```

---

## 2. Configure JWT

```properties
# application.properties

security.jwt.secret=${JWT_SECRET}
security.jwt.expiration-ms=3600000
security.jwt.refresh-expiration-ms=604800000
security.jwt.issuer=my-application
```

**Important:**
Application will NOT start if `security.jwt.secret` is missing.

Never commit the secret into source control. Use environment variables.

---

## 3. Implement `UserAccountProvider` (Only Required Step)

This tells the framework how to fetch users from your database.

```java
@Service
public class JpaUserAccountProvider implements UserAccountProvider {

    private final UserRepository repository;

    public JpaUserAccountProvider(UserRepository repository) {
        this.repository = repository;
    }

    @Override
    public Optional<UserAccount> findByUsername(String username) {
        return repository.findByUsername(username)
                .map(user -> new UserAccount() {
                    public String getId() { return user.getId(); }
                    public String getUsername() { return user.getUsername(); }
                    public String getPassword() { return user.getPassword(); }
                    public Set<String> getRoles() { return user.getRoles(); }
                    public Set<String> getPermissions() { return user.getPermissions(); }
                });
    }
}
```

That’s it.
No filters.
No security config.
No JWT wiring.

---

## Built-in Endpoints

| Method | Path       | Description                                          |
| ------ | ---------- | ---------------------------------------------------- |
| POST   | `/login`   | Authenticate user and return access + refresh tokens |
| POST   | `/refresh` | Rotate refresh token and issue new token pair        |
| POST   | `/logout`  | Revoke refresh token                                 |

---

# Authorization Annotations

You protect controllers declaratively.

```java
@GetMapping("/admin")
@RequireRole("ADMIN")
public String admin() { ... }

@GetMapping("/reports")
@RequireRole({"ADMIN","MANAGER"})
public String reports() { ... }

@DeleteMapping("/donation/{id}")
@RequirePermission("donation:delete")
public void delete() { ... }

@GetMapping("/users/{userId}")
@RequireOwner("#userId")
public User profile(@PathVariable String userId) { ... }
```

---

## Authorization Flow

```
HTTP Request
   ↓
JwtAuthenticationFilter
   ↓
SecurityContextFilter
   ↓
Controller
   ↓
AuthorizationAspect intercepts annotation
   ↓
AuthorizationManager validates access
   ↓
Allow OR throw SecurityAuthorizationException
```

---

# Public Endpoints

You can whitelist endpoints:

```properties
security.public-endpoints=/register,/health,/docs/**
```

`/login`, `/refresh`, `/logout` are public by default.

---

# Error Responses

### 401 — Unauthenticated

```json
{
  "error": "UNAUTHORIZED",
  "message": "Authentication required to access this resource",
  "timestamp": "2026-03-01T14:00:00Z"
}
```

### 403 — Forbidden

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

# Refresh Token Rotation

Every `/refresh` call:

1. Old refresh token is revoked
2. New access + refresh token issued
3. New refresh token hash stored

### Replay Detection

If a revoked refresh token is reused → **all tokens for that user are revoked**

This prevents stolen token usage.

---

## Custom Token Store

Default: `InMemoryRefreshTokenStore`

For production, implement `RefreshTokenStore`:

```java
@Service
public class JpaRefreshTokenStore implements RefreshTokenStore {
    // store tokens in database
}
```

Spring automatically replaces the default when your bean exists.

---

# Overriding Defaults

All components use `@ConditionalOnMissingBean`.

You can override:

| Bean                  | Default                       |
| --------------------- | ----------------------------- |
| AuthorizationManager  | DefaultAuthorizationManager   |
| RefreshTokenStore     | InMemoryRefreshTokenStore     |
| PasswordEncoder       | BCryptPasswordEncoder         |
| SecurityFilterChain   | Built-in stateless JWT chain  |
| AuthenticationAdapter | JWT + SpringSecurity adapters |
| Exception Handlers    | JSON handlers                 |

Example:

```java
@Bean
public AuthorizationManager authorizationManager() {
    return new CustomAuthorizationManager();
}
```

---

# SecurityUserContext

Access authenticated user anywhere in request:

```java
AuthenticatedUser user = SecurityUserContext.getCurrentUser();
AuthenticatedUser user = SecurityUserContext.requireCurrentUser();
```

⚠ ThreadLocal based — not available in async threads (`@Async`, schedulers, Kafka listeners).

---

# Architecture

### Modules

```
security-core          → Interfaces & annotations
security-autoconfigure → Spring Boot auto configuration
security-starter       → Starter dependency
```

### Request Lifecycle

```
HTTP Request
   ↓
JwtAuthenticationFilter (verify JWT)
   ↓
SecurityContextFilter (convert to AuthenticatedUser)
   ↓
Controller
   ↓
AuthorizationAspect
   ↓
Response
```

---

# What This Starter Solves

• Eliminates manual Spring Security setup
• Provides consistent REST error handling
• Simplifies authorization logic
• Adds ownership-level authorization
• Secure refresh token rotation
• Fully customizable

---

# Recommended Practices

* Use a strong 256-bit secret
* Always use HTTPS
* Replace InMemoryRefreshTokenStore in clustered deployment
* Keep access token lifetime short
* Monitor refresh token replay logs

---

# Project Structure

```
spring-security-explainer/
├── security-core/
├── security-autoconfigure/
├── security-starter/
├── security-test/
└── testing-security-explainer/   (demo app)
```

---

# Future Direction

The framework is designed to support multiple authentication providers:

* JWT (current)
* OAuth2
* Keycloak
* External Identity Providers

Without changing controller code.

---

**You now have a pluggable application-level security layer for Spring Boot.**
