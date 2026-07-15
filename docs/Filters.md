# Filters

This document describes every `OncePerRequestFilter` in the filter chain, the order they run in, and what each one does.

---

## Filter Order (INTERNAL Mode)

```
Incoming HTTP Request
        │
        ▼
[UsernamePasswordAuthenticationFilter position]
        │
        ▼ (registered BEFORE UsernamePasswordAuthenticationFilter)
┌─────────────────────────────────────────────────────────┐
│  JwtAuthenticationFilter                                │
│  • Reads Authorization: Bearer <token> header           │
│  • Calls JwtService.verifyToken(token)                  │
│  • Success: sets JwtAuthenticationToken in              │
│    SecurityContextHolder                                │
│  • Failure: calls SecurityContextHolder.clearContext()  │
│  • Always: continues filter chain                       │
└─────────────────────────────────────────────────────────┘
        │
        ▼ (registered AFTER JwtAuthenticationFilter)
┌─────────────────────────────────────────────────────────┐
│  SecurityContextFilter                                  │
│  • Reads Authentication from SecurityContextHolder      │
│  • If authenticated: finds matching AuthenticationAdapter│
│  • Converts to AuthenticatedUser                        │
│  • Stores in SecurityUserContext (ThreadLocal)          │
│  • Finally block: SecurityUserContext.clear()           │
└─────────────────────────────────────────────────────────┘
        │
        ▼
[Spring Security authorization filter]
        │
        ▼
[Controller → AOP authorization checks]
```

## Filter Order (OAUTH2 / KEYCLOAK Mode)

```
Incoming HTTP Request
        │
        ▼
┌─────────────────────────────────────────────────────────┐
│  BearerTokenAuthenticationFilter  (Spring OAuth2)       │
│  • Validates JWT against JWKS (fetched from issuer-uri) │
│  • Sets JwtAuthenticationToken in SecurityContextHolder  │
└─────────────────────────────────────────────────────────┘
        │
        ▼ (registered AFTER BearerTokenAuthenticationFilter)
┌─────────────────────────────────────────────────────────┐
│  SecurityContextFilter  (same as INTERNAL mode)         │
│  Uses OAuth2AuthenticationAdapter or                    │
│  KeycloakAuthenticationAdapter                          │
└─────────────────────────────────────────────────────────┘
```

---

## `JwtAuthenticationFilter`

**Class:** `com.sricharan.security.autoconfigure.filter.JwtAuthenticationFilter`
**Active:** INTERNAL mode only
**Registered:** via `FilterRegistrationBean` with `setEnabled(false)` (prevents auto-registration as a servlet filter — the Spring Security filter chain registers it at the correct position)

### Behaviour

1. Reads the `Authorization` header
2. Checks that it starts with `Bearer `
3. Extracts the raw token (strips the `Bearer ` prefix)
4. Calls `JwtService.verifyToken(token)` — validates signature, expiry, issuer, and token type (`type=access`)
5. On **success**: creates `JwtAuthenticationToken` and sets it in `SecurityContextHolder`
6. On **failure** (`JWTVerificationException`): calls `SecurityContextHolder.clearContext()` and logs at DEBUG. Continues the filter chain — Spring Security's own authorization filter will reject the unauthenticated request with a 401.

### Key Design Decision

The filter **does not write the 401 response itself**. It clears the context and lets the filter chain continue. The `JsonAuthenticationEntryPoint` handles the 401 response when Spring Security's authorization layer sees an unauthenticated request on a protected endpoint. This separates the concerns of token parsing and response generation.

---

## `SecurityContextFilter`

**Class:** `com.sricharan.security.autoconfigure.filter.SecurityContextFilter`
**Active:** All modes
**Registered:** via `FilterRegistrationBean` with `setEnabled(false)` (same pattern as above)

### Behaviour

1. Reads `Authentication` from `SecurityContextHolder.getContext().getAuthentication()`
2. If the authentication is non-null and `isAuthenticated() == true`:
   - Iterates the priority-sorted list of `AuthenticationAdapter` beans
   - Calls `adapter.supports(authentication)` for each
   - When a matching adapter is found, calls `adapter.convert(authentication)`
   - Stores the resulting `AuthenticatedUser` in `SecurityUserContext.setCurrentUser(user)`
3. Continues the filter chain
4. In `finally`: calls `SecurityUserContext.clear()` — **always executed**, even on exception, preventing ThreadLocal leaks in pooled threads

### ThreadLocal Cleanup

The `finally` block that clears `SecurityUserContext` is critical for correctness in servlet containers that pool threads. Without it, the `AuthenticatedUser` from a previous request could leak into the next request served by the same thread.

---

## Why `FilterRegistrationBean.setEnabled(false)`?

Spring Boot automatically registers every `Filter` bean as a standalone servlet filter. However, for security filters, we need them registered in the **Spring Security filter chain at a specific position**, not as standalone servlet filters (which would run at the wrong order and outside the security context).

The `FilterRegistrationBean` with `setEnabled(false)` tells Spring Boot's auto-configuration to skip auto-registration as a servlet filter. The filters are then manually added to the security filter chain via:

```java
http
    .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
    .addFilterAfter(securityContextFilter, JwtAuthenticationFilter.class);
```

---

## `JsonAuthenticationEntryPoint`

**Class:** `com.sricharan.security.autoconfigure.handler.JsonAuthenticationEntryPoint`
**Triggered:** When Spring Security rejects an unauthenticated request (no valid auth in security context)

Writes a `401 UNAUTHORIZED` JSON response:
```json
{
  "error": "UNAUTHORIZED",
  "message": "Authentication required to access this resource",
  "timestamp": "2026-01-15T10:30:00Z"
}
```

Also emits a `UNAUTHORIZED` `SecurityAuditEvent`.

---

## `JsonAccessDeniedHandler`

**Class:** `com.sricharan.security.autoconfigure.handler.JsonAccessDeniedHandler`
**Triggered:** When Spring Security's own access control (e.g., `hasRole()` in `authorizeHttpRequests`) denies access

Writes a `403 FORBIDDEN` JSON response. Note: `SecurityAuthorizationException` from `@RequireRole`/`@RequirePermission`/`@RequireOwner` is handled by `SecurityExceptionHandler` (`@RestControllerAdvice`), not by this handler.

---

## Adding Custom Filters

To add your own filter to the security chain, declare it as a `@Bean` and configure it in a custom `SecurityFilterChain`:

```java
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, ...) throws Exception {
        // ... base configuration
        http.addFilterBefore(new RequestIdFilter(), JwtAuthenticationFilter.class);
        return http.build();
    }
}
```
