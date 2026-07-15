# JWT Internals

This document describes how JSON Web Tokens are generated, validated, and used within Spring Security Explainer's INTERNAL mode.

---

## Algorithm & Library

| Detail | Value |
|---|---|
| Signing algorithm | HMAC-SHA256 (HS256) |
| Library | `com.auth0:java-jwt` |
| Secret type | Symmetric HMAC secret (shared between generation and verification) |
| Suitability | Single service, or services that share the same secret via environment variable |

> **Limitation:** HS256 with a shared secret is not suitable for microservice architectures where each service independently validates tokens without access to the signing secret. For those architectures, RS256/ES256 with JWKS is needed (planned for v1.3.x — see [ROADMAP.md](../ROADMAP.md)).

---

## Access Token Structure

```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "john.doe",
    "userId": "user-uuid-123",
    "roles": ["USER"],
    "permissions": ["post:read"],
    "type": "access",
    "jti": "550e8400-e29b-41d4-a716-446655440000",
    "iss": "my-application",
    "iat": 1736929800,
    "exp": 1736933400
  }
}
```

| Claim | Source | Purpose |
|---|---|---|
| `sub` | `UserAccount.getUsername()` | JWT subject — identifies the user |
| `userId` | `UserAccount.getId()` | Application-level user ID (may differ from username) |
| `roles` | `UserAccount.getRoles()` | Roles for authorization checks |
| `permissions` | `UserAccount.getPermissions()` | Fine-grained permissions |
| `type` | Hardcoded `"access"` | Prevents refresh tokens from being used as access tokens |
| `jti` | `UUID.randomUUID()` | Unique token ID — can be used for revocation lists |
| `iss` | `security.jwt.issuer` | Issuer claim — validated during verification |
| `iat` | Current time | Issued-at timestamp |
| `exp` | `iat + security.jwt.expiration-ms` | Expiry timestamp |

---

## Refresh Token Structure

Refresh tokens are intentionally **minimal**. They only contain the claims needed to look up the user and rotate the token pair:

```json
{
  "payload": {
    "sub": "john.doe",
    "type": "refresh",
    "jti": "another-uuid",
    "iss": "my-application",
    "iat": 1736929800,
    "exp": 1737534600
  }
}
```

**No roles or permissions are embedded.** When a refresh token is consumed, the library calls `UserAccountProvider.findByUsername()` to reload the user's current roles and permissions. This ensures that:
- Permission changes take effect on the next token rotation, not just at the next login
- The refresh token cannot be used to escalate privileges

---

## Token Verification

`JwtService.verifyToken()` performs the following checks in order:

1. **Signature** — HMAC-SHA256 signature matches the configured secret
2. **Expiry** — `exp` claim is in the future
3. **Issuer** — `iss` claim matches `security.jwt.issuer`
4. **Token type** — `type` claim equals `"access"` (prevents refresh tokens being accepted as access tokens)

If any check fails, a `JWTVerificationException` is thrown, the `JwtAuthenticationFilter` clears the security context, and the request proceeds unauthenticated.

---

## Refresh Token Security Model

Raw refresh tokens are **never stored in the database**. The storage flow is:

```
Client receives: rawRefreshToken (random UUID embedded in JWT)
Library stores:  SHA-256(rawRefreshToken)

On /refresh:
Client sends:   rawRefreshToken
Library checks: SHA-256(rawRefreshToken) in store → match
```

This means that even if the token store (Redis or in-memory) is compromised, the attacker cannot construct valid refresh tokens from the hashes.

### Replay Attack Protection

The `consumeForRotation` operation is the most security-critical step. In Redis mode, it is implemented as a Lua script that runs atomically on the Redis server:

```lua
-- Simplified pseudocode of the Lua script
local key = KEYS[1]  -- hash key for this token
local ttl = redis.call('TTL', key)

if ttl == -2 then
  return -2  -- key does not exist (not found)
end

local revoked = redis.call('HGET', key, 'revoked')
if revoked == '1' then
  return -1  -- already revoked (REPLAY DETECTED)
end

local expires = tonumber(redis.call('HGET', key, 'expiresAt'))
if expires < currentTime then
  return -3  -- expired
end

-- Mark as revoked atomically
redis.call('HSET', key, 'revoked', '1')
return 1  -- success
```

When a replay is detected (return value `-1`), the library immediately calls `revokeAllForUser()` — revoking **all** refresh tokens for that user. This is the correct response to a detected token theft: the assumption is that an attacker got hold of a refresh token that was already used, which means either the user or the attacker has a valid session, and both should be evicted.

---

## Token Generation Flow

```java
// 1. AuthController.login() calls:
String accessToken = jwtService.generateToken(userAccount);
String refreshToken = jwtService.generateRefreshToken(userAccount);

// 2. JwtService builds the access token:
JWT.create()
   .withSubject(user.getUsername())
   .withClaim("userId", user.getId())
   .withClaim("roles", new ArrayList<>(user.getRoles()))
   .withClaim("permissions", new ArrayList<>(user.getPermissions()))
   .withClaim("type", "access")
   .withJWTId(UUID.randomUUID().toString())
   .withIssuer(jwtProperties.getIssuer())
   .withIssuedAt(now)
   .withExpiresAt(now.plus(expirationMs))
   .sign(Algorithm.HMAC256(secret))

// 3. Refresh token (no roles/permissions):
JWT.create()
   .withSubject(user.getUsername())
   .withClaim("type", "refresh")
   .withJWTId(UUID.randomUUID().toString())
   // ... same issuer/iat/exp
```

---

## Configuring JWT Properties

```properties
# Required (INTERNAL mode only)
security.jwt.secret=your-super-secret-minimum-32-character-key

# Optional
security.jwt.expiration-ms=900000         # 15 minutes (recommended for production)
security.jwt.refresh-expiration-ms=2592000000  # 30 days
security.jwt.issuer=my-api-service
```

**Generating a strong secret:**
```bash
openssl rand -base64 32
# Example output: K8q+mNpWxZvJ7LcRhDfGnQeB5tA3ysYiU2oP6wMXkT0=
```

---

## Login Response Shape

```http
POST /login
Content-Type: application/json

{ "username": "alice", "password": "s3cr3t" }
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "accessToken": "eyJhbGciOiJIUzI1NiJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiJ9...",
  "tokenType": "Bearer",
  "expiresIn": 3600
}
```

| Field | Type | Description |
|---|---|---|
| `accessToken` | `string` | JWT for API requests — include as `Authorization: Bearer <token>` |
| `refreshToken` | `string` | JWT for token rotation — send to `POST /refresh` |
| `tokenType` | `string` | Always `"Bearer"` |
| `expiresIn` | `number` | Access token TTL in seconds |
