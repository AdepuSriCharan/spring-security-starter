package com.sricharan.security.autoconfigure.controller;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.sricharan.security.autoconfigure.jwt.JwtService;
import com.sricharan.security.autoconfigure.jwt.TokenResponse;
import com.sricharan.security.autoconfigure.token.TokenHashUtil;
import com.sricharan.security.core.account.UserAccount;
import com.sricharan.security.core.account.UserAccountProvider;
import com.sricharan.security.core.token.RefreshTokenStore;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Built-in Login, Token Refresh, and Logout API.
 *
 * <p>Only active if the developer has provided a {@link UserAccountProvider} bean.
 *
 * <p>Endpoints:
 * <ul>
 *   <li>{@code POST /login} — authenticates and returns access + refresh tokens</li>
 *   <li>{@code POST /refresh} — exchanges a valid refresh token for a new token pair (rotation)</li>
 *   <li>{@code POST /logout} — revokes a refresh token</li>
 * </ul>
 *
 * <p><strong>Refresh Token Rotation:</strong> Every call to {@code /refresh} invalidates
 * the old refresh token and issues a new one. If a revoked token is reused, all tokens
 * for the affected user are revoked (theft detection).
 */
@RestController
public class AuthController {

    private final ObjectProvider<UserAccountProvider> userAccountProviderRef;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenStore refreshTokenStore;

    public AuthController(
            ObjectProvider<UserAccountProvider> userAccountProviderRef,
            PasswordEncoder passwordEncoder,
            JwtService jwtService,
            RefreshTokenStore refreshTokenStore) {
        this.userAccountProviderRef = userAccountProviderRef;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.refreshTokenStore = refreshTokenStore;
    }

    // ── Login ──────────────────────────────────────────────

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {

        UserAccountProvider provider = userAccountProviderRef.getIfAvailable();
        if (provider == null) {
            return errorResponse(HttpStatus.NOT_IMPLEMENTED,
                    "No UserAccountProvider configured in the application context.");
        }

        if (request.getUsername() == null || request.getPassword() == null) {
            return errorResponse(HttpStatus.BAD_REQUEST,
                    "Username and password are required.");
        }

        Optional<UserAccount> userOpt = provider.findByUsername(request.getUsername());

        if (userOpt.isEmpty()) {
            return errorResponse(HttpStatus.UNAUTHORIZED, "Invalid username or password.");
        }

        UserAccount user = userOpt.get();

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            return errorResponse(HttpStatus.UNAUTHORIZED, "Invalid username or password.");
        }

        return ResponseEntity.ok(issueAndStoreTokenPair(user));
    }

    // ── Refresh (with token rotation) ─────────────────────

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody RefreshRequest request) {

        UserAccountProvider provider = userAccountProviderRef.getIfAvailable();
        if (provider == null) {
            return errorResponse(HttpStatus.NOT_IMPLEMENTED,
                    "No UserAccountProvider configured.");
        }

        if (request.getRefreshToken() == null || request.getRefreshToken().isBlank()) {
            return errorResponse(HttpStatus.BAD_REQUEST, "Refresh token is required.");
        }

        try {
            // 1. Verify the JWT signature and expiry
            String username = jwtService.verifyRefreshToken(request.getRefreshToken());

            // 2. Check the token store (revocation / replay detection)
            String tokenHash = TokenHashUtil.sha256(request.getRefreshToken());
            if (!refreshTokenStore.isValid(tokenHash)) {
                // Token was already used or revoked — possible theft
                return errorResponse(HttpStatus.UNAUTHORIZED,
                        "Refresh token has been revoked. Please log in again.");
            }

            // 3. Revoke the old token (rotation)
            refreshTokenStore.revoke(tokenHash);

            // 4. Re-fetch the user to get fresh roles/permissions
            Optional<UserAccount> userOpt = provider.findByUsername(username);
            if (userOpt.isEmpty()) {
                return errorResponse(HttpStatus.UNAUTHORIZED, "User no longer exists.");
            }

            // 5. Issue new token pair
            return ResponseEntity.ok(issueAndStoreTokenPair(userOpt.get()));

        } catch (JWTVerificationException e) {
            return errorResponse(HttpStatus.UNAUTHORIZED,
                    "Invalid or expired refresh token.");
        }
    }

    // ── Logout ────────────────────────────────────────────

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody RefreshRequest request) {

        if (request.getRefreshToken() == null || request.getRefreshToken().isBlank()) {
            return errorResponse(HttpStatus.BAD_REQUEST, "Refresh token is required.");
        }

        String tokenHash = TokenHashUtil.sha256(request.getRefreshToken());
        refreshTokenStore.revoke(tokenHash);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("message", "Logged out successfully.");
        body.put("timestamp", Instant.now().toString());

        return ResponseEntity.ok(body);
    }

    // ── Helpers ───────────────────────────────────────────

    private TokenResponse issueAndStoreTokenPair(UserAccount user) {
        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        // Store the hash of the new refresh token
        String tokenHash = TokenHashUtil.sha256(refreshToken);
        Instant expiresAt = Instant.now().plusMillis(jwtService.getRefreshExpirationMs());
        refreshTokenStore.store(user.getId(), tokenHash, expiresAt);

        return new TokenResponse(accessToken, refreshToken, jwtService.getExpirationMs());
    }

    private ResponseEntity<Map<String, Object>> errorResponse(HttpStatus status, String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", status.name());
        body.put("message", message);
        body.put("timestamp", Instant.now().toString());
        return ResponseEntity.status(status).body(body);
    }

    // ── Request DTOs ──────────────────────────────────────

    public static class LoginRequest {
        private String username;
        private String password;

        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }

    public static class RefreshRequest {
        private String refreshToken;

        public String getRefreshToken() { return refreshToken; }
        public void setRefreshToken(String refreshToken) { this.refreshToken = refreshToken; }
    }
}
