# Authentication Flow

This document traces every authentication path from the raw HTTP request to the populated `AuthenticatedUser` — for all three authentication modes.

---

## INTERNAL Mode — `/login` Flow

```mermaid
sequenceDiagram
    participant Client
    participant AuthController
    participant UserAccountProvider
    participant PasswordEncoder
    participant JwtService
    participant RefreshTokenStore
    participant SecurityEventRecorder

    Client->>AuthController: POST /login { username, password }
    AuthController->>UserAccountProvider: findByUsername(username)
    alt user not found
        UserAccountProvider-->>AuthController: Optional.empty()
        AuthController->>SecurityEventRecorder: LOGIN_FAILURE (user_not_found)
        AuthController-->>Client: 401 UNAUTHORIZED
    else user found
        UserAccountProvider-->>AuthController: UserAccount
        AuthController->>PasswordEncoder: matches(rawPassword, hashedPassword)
        alt password mismatch
            PasswordEncoder-->>AuthController: false
            AuthController->>SecurityEventRecorder: LOGIN_FAILURE (password_mismatch)
            AuthController-->>Client: 401 UNAUTHORIZED
        else password correct
            PasswordEncoder-->>AuthController: true
            AuthController->>JwtService: generateToken(userAccount)
            JwtService-->>AuthController: accessToken (HS256 JWT)
            AuthController->>JwtService: generateRefreshToken(userAccount)
            JwtService-->>AuthController: refreshToken (HS256 JWT)
            AuthController->>RefreshTokenStore: store(userId, sha256(refreshToken), expiresAt)
            AuthController->>SecurityEventRecorder: LOGIN_SUCCESS
            AuthController-->>Client: 200 { accessToken, refreshToken, tokenType, expiresIn }
        end
    end
```

---

## INTERNAL Mode — Protected Request Flow

```mermaid
sequenceDiagram
    participant Client
    participant JwtAuthenticationFilter
    participant SecurityContextHolder
    participant SecurityContextFilter
    participant AuthenticationAdapter
    participant SecurityUserContext
    participant Controller
    participant AuthorizationAspect

    Client->>JwtAuthenticationFilter: GET /api/data  Authorization: Bearer <token>
    JwtAuthenticationFilter->>JwtAuthenticationFilter: extract token from header
    JwtAuthenticationFilter->>JwtAuthenticationFilter: jwtService.verifyToken(token)
    alt invalid or expired token
        JwtAuthenticationFilter->>SecurityContextHolder: clearContext()
        Note over JwtAuthenticationFilter: request continues without authentication
        JwtAuthenticationFilter-->>Client: Spring Security rejects → 401 JSON
    else valid token
        JwtAuthenticationFilter->>SecurityContextHolder: setAuthentication(JwtAuthenticationToken)
        JwtAuthenticationFilter->>SecurityContextFilter: continue filter chain
        SecurityContextFilter->>SecurityContextHolder: getAuthentication()
        SecurityContextFilter->>AuthenticationAdapter: supports(authentication)?
        AuthenticationAdapter-->>SecurityContextFilter: true (JwtAuthenticationAdapter)
        SecurityContextFilter->>AuthenticationAdapter: convert(authentication)
        AuthenticationAdapter-->>SecurityContextFilter: AuthenticatedUser
        SecurityContextFilter->>SecurityUserContext: setCurrentUser(user)
        SecurityContextFilter->>Controller: continue
        Controller->>AuthorizationAspect: @RequireRole / @RequirePermission / @RequireOwner
        AuthorizationAspect->>SecurityUserContext: requireCurrentUser()
        SecurityUserContext-->>AuthorizationAspect: AuthenticatedUser
        AuthorizationAspect->>AuthorizationAspect: check roles/permissions/ownership
        alt authorized
            AuthorizationAspect->>Controller: proceed
            Controller-->>Client: 200 response
        else denied
            AuthorizationAspect-->>Client: SecurityAuthorizationException → 403 JSON
        end
    end
    Note over SecurityContextFilter: finally: SecurityUserContext.clear()
```

---

## INTERNAL Mode — Token Refresh Flow

```mermaid
sequenceDiagram
    participant Client
    participant AuthController
    participant JwtService
    participant RefreshTokenStore
    participant UserAccountProvider
    participant SecurityEventRecorder

    Client->>AuthController: POST /refresh { refreshToken }
    AuthController->>JwtService: verifyRefreshToken(refreshToken)
    alt invalid or expired JWT signature
        JwtService-->>AuthController: JWTVerificationException
        AuthController->>SecurityEventRecorder: REFRESH_FAILURE (invalid_or_expired_token)
        AuthController-->>Client: 401 UNAUTHORIZED
    else valid JWT
        JwtService-->>AuthController: username (subject)
        AuthController->>AuthController: sha256(refreshToken) → tokenHash
        AuthController->>RefreshTokenStore: consumeForRotation(tokenHash)
        alt token already revoked (replay attack)
            RefreshTokenStore-->>AuthController: false (-1 from Lua script)
            RefreshTokenStore->>RefreshTokenStore: revokeAllForUser(userId)
            AuthController->>SecurityEventRecorder: REFRESH_REPLAY_DETECTED
            AuthController-->>Client: 401 UNAUTHORIZED
        else token valid
            RefreshTokenStore-->>AuthController: true
            AuthController->>UserAccountProvider: findByUsername(username)
            AuthController->>JwtService: generateToken(freshUser)
            AuthController->>JwtService: generateRefreshToken(freshUser)
            AuthController->>RefreshTokenStore: store(userId, sha256(newToken), expiresAt)
            AuthController->>SecurityEventRecorder: REFRESH_SUCCESS
            AuthController-->>Client: 200 { new accessToken, new refreshToken }
        end
    end
```

### Replay Attack Detection

The `consumeForRotation` method is the security heart of the refresh flow. In Redis mode, it executes an atomic Lua script that:

1. Checks if the token hash exists
2. Checks if it has expired
3. Checks if it has already been revoked (`revoked = "1"`)
4. If revoked: returns `-1` (replay detected — caller revokeAllForUser)
5. If valid: atomically sets `revoked = "1"` and returns `1`

This ensures that even under concurrent requests, a refresh token can only be consumed once.

---

## OAUTH2 Mode — Request Flow

```mermaid
sequenceDiagram
    participant Client
    participant BearerTokenFilter as BearerTokenAuthenticationFilter (Spring)
    participant JwksEndpoint as IDP JWKS Endpoint
    participant SecurityContextFilter
    participant OAuth2Adapter as OAuth2AuthenticationAdapter

    Client->>BearerTokenFilter: GET /api/data  Authorization: Bearer <oidc-token>
    BearerTokenFilter->>JwksEndpoint: fetch JWKS (cached)
    BearerTokenFilter->>BearerTokenFilter: verify JWT signature + expiry
    BearerTokenFilter->>BearerTokenFilter: set JwtAuthenticationToken in SecurityContextHolder
    BearerTokenFilter->>SecurityContextFilter: continue
    SecurityContextFilter->>OAuth2Adapter: supports(JwtAuthenticationToken)? → true
    SecurityContextFilter->>OAuth2Adapter: convert(authentication)
    OAuth2Adapter->>OAuth2Adapter: extract username-claim, user-id-claim, roles-claim, permissions-claim
    OAuth2Adapter-->>SecurityContextFilter: AuthenticatedUser
    SecurityContextFilter->>SecurityContextFilter: SecurityUserContext.setCurrentUser(user)
    SecurityContextFilter-->>Client: request proceeds to controller
```

Claim names are configurable:
```properties
security.oauth2.username-claim=preferred_username
security.oauth2.user-id-claim=sub
security.oauth2.roles-claim=roles
security.oauth2.permissions-claim=permissions
```

---

## KEYCLOAK Mode — Role Extraction

KEYCLOAK mode extends OAUTH2 mode. The only difference is `KeycloakAuthenticationAdapter`, which extracts Keycloak's nested role structure:

```json
{
  "realm_access": {
    "roles": ["ADMIN", "USER"]
  },
  "resource_access": {
    "my-client": {
      "roles": ["client-role-a"]
    }
  }
}
```

| JWT claim path | Maps to |
|---|---|
| `realm_access.roles` | `AuthenticatedUser.getRoles()` |
| `resource_access.<clientId>.roles` | `AuthenticatedUser.getPermissions()` |

---

## Token Structure (INTERNAL Mode)

### Access Token Claims

| Claim | Value | Description |
|---|---|---|
| `sub` | username | JWT subject |
| `userId` | user's unique ID | Application user ID |
| `roles` | `["ADMIN", "USER"]` | Roles array |
| `permissions` | `["post:delete"]` | Permissions array |
| `type` | `"access"` | Token type discriminator |
| `jti` | UUID | Unique token ID |
| `iss` | configured issuer | Token issuer |
| `iat` | issued-at timestamp | |
| `exp` | expiry timestamp | |

### Refresh Token Claims

Refresh tokens intentionally contain **minimal claims** — only `sub`, `type=refresh`, `jti`, `iss`, `iat`, `exp`. Roles and permissions are re-fetched from `UserAccountProvider` on every refresh. This ensures that permission changes take effect on the next token rotation without waiting for the access token to expire.

---

## Logout Flow

```
POST /logout { refreshToken }
    │
    ▼ sha256(refreshToken)
    │
    ▼ refreshTokenStore.revoke(tokenHash)
    │   marks revoked = "1" in store
    │
    ▼ SecurityEventRecorder: LOGOUT + SESSION_REVOKED
    │
    ▼ 200 { message: "Logged out successfully." }
```
