# Exception Handling

This document describes every security exception, its HTTP status, JSON response shape, and how to customise the error responses.

---

## Exception Architecture

The library uses two complementary mechanisms for error responses:

```
Security Error
      │
      ├─► Spring Security infrastructure errors (401, 403 from filter chain)
      │       Handled by: JsonAuthenticationEntryPoint (401)
      │                   JsonAccessDeniedHandler (403)
      │
      └─► Application-layer authorization errors (from @RequireRole / @Permission / @Owner)
              Handled by: SecurityExceptionHandler (@RestControllerAdvice)
                          catches SecurityAuthorizationException
```

---

## 401 Unauthorized

**Trigger:** An unauthenticated request reaches a protected endpoint (no `Authorization` header, expired token, or invalid token signature).

**Handler:** `JsonAuthenticationEntryPoint`

**Response:**
```json
{
  "error": "UNAUTHORIZED",
  "message": "Authentication required to access this resource",
  "timestamp": "2026-01-15T10:30:00Z"
}
```

**Audit event emitted:** `UNAUTHORIZED`

---

## 401 Unauthorized — Invalid Credentials

**Trigger:** `POST /login` with a non-existent username or incorrect password.

**Handler:** `AuthController` — directly constructs the response

**Response:**
```json
{
  "error": "UNAUTHORIZED",
  "message": "Invalid username or password.",
  "timestamp": "2026-01-15T10:30:00Z"
}
```

**Audit event emitted:** `LOGIN_FAILURE`

---

## 401 Unauthorized — Refresh Token Rejected

**Trigger:** `POST /refresh` with an expired, revoked, or replayed refresh token.

**Response:**
```json
{
  "error": "UNAUTHORIZED",
  "message": "Refresh token is invalid or has expired.",
  "timestamp": "2026-01-15T10:30:00Z"
}
```

**Audit event emitted:**
- `REFRESH_FAILURE` — expired or not found
- `REFRESH_REPLAY_DETECTED` — token already consumed (triggers `revokeAllForUser`)

---

## 403 Forbidden — Role Check Failed

**Trigger:** `@RequireRole` annotation on a controller method — user lacks all required roles.

**Handler:** `SecurityExceptionHandler` catches `SecurityAuthorizationException`

**Response:**
```json
{
  "error": "FORBIDDEN",
  "message": "Access denied for user 'john'. Required role: [ADMIN]. User has: [USER]",
  "type": "ROLE",
  "required": ["ADMIN"],
  "actual": ["USER"],
  "timestamp": "2026-01-15T10:30:00Z"
}
```

**Audit event emitted:** `ACCESS_DENIED` with `details.type=ROLE`

---

## 403 Forbidden — Permission Check Failed

**Trigger:** `@RequirePermission` annotation on a controller method — user lacks all required permissions.

**Response:**
```json
{
  "error": "FORBIDDEN",
  "message": "Access denied for user 'john'. Required permission: [post:delete]. User has: []",
  "type": "PERMISSION",
  "required": ["post:delete"],
  "actual": [],
  "timestamp": "2026-01-15T10:30:00Z"
}
```

**Audit event emitted:** `ACCESS_DENIED` with `details.type=PERMISSION`

---

## 403 Forbidden — Ownership Check Failed

**Trigger:** `@RequireOwner` annotation on a controller method — authenticated user is not the owner of the resource.

**Response:**
```json
{
  "error": "FORBIDDEN",
  "message": "Access denied for user 'john'. Not the owner of resource 'admin-id'.",
  "type": "OWNERSHIP",
  "resourceId": "admin-id",
  "timestamp": "2026-01-15T10:30:00Z"
}
```

**Audit event emitted:** `ACCESS_DENIED` with `details.type=OWNERSHIP`

---

## 401 Unauthorized — Missing `SecurityUserContext`

**Trigger:** `SecurityUserContext.requireCurrentUser()` is called in a method that is not running within the security filter chain (e.g., in a service accessed outside of an HTTP request, in a scheduled task, or in an `@Async` method).

**Handler:** `SecurityExceptionHandler` catches `IllegalStateException` messages containing `"SecurityUserContext"`.

**Response:**
```json
{
  "error": "UNAUTHORIZED",
  "message": "Authentication required to access this resource",
  "timestamp": "2026-01-15T10:30:00Z"
}
```

---

## Response Shape Summary

| Scenario | HTTP Status | `error` field | Extra fields |
|---|---|---|---|
| No token / invalid token | `401` | `UNAUTHORIZED` | — |
| Bad credentials at login | `401` | `UNAUTHORIZED` | — |
| Expired/revoked refresh token | `401` | `UNAUTHORIZED` | — |
| Replay detected | `401` | `UNAUTHORIZED` | — |
| Role check failed | `403` | `FORBIDDEN` | `type`, `required`, `actual` |
| Permission check failed | `403` | `FORBIDDEN` | `type`, `required`, `actual` |
| Ownership check failed | `403` | `FORBIDDEN` | `type`, `resourceId` |

---

## Customising Error Responses

### Custom 401 Format

```java
@Component
public class MyAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write("""
            {
              "status": 401,
              "code": "AUTH_REQUIRED",
              "path": "%s",
              "timestamp": "%s"
            }
            """.formatted(request.getRequestURI(), Instant.now()));
    }
}
```

### Custom 403 Format

```java
@Component
public class MyAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
            AccessDeniedException accessDeniedException) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.getWriter().write("""
            {
              "status": 403,
              "code": "ACCESS_DENIED",
              "path": "%s"
            }
            """.formatted(request.getRequestURI()));
    }
}
```

### Custom Authorization Exception Format

Add your own `@ExceptionHandler` in a `@RestControllerAdvice` for `SecurityAuthorizationException`:

```java
@RestControllerAdvice
public class MySecurityExceptionHandler {

    @ExceptionHandler(SecurityAuthorizationException.class)
    public ResponseEntity<ApiError> handle(SecurityAuthorizationException ex) {
        return ResponseEntity.status(403)
               .body(new ApiError(ex.getType().name(), ex.getMessage()));
    }
}
```

> **Note:** If you declare your own `@ExceptionHandler` for `SecurityAuthorizationException`, be aware that `SecurityExceptionHandler` (auto-configured by the starter) also handles this exception. Only one handler can win. The starter's handler is registered as a `@Bean` with `@ConditionalOnMissingBean`, but since both are `@RestControllerAdvice`, Spring uses `@Order` to determine precedence. Disable the starter's handler by overriding the `securityExceptionHandler` bean.
