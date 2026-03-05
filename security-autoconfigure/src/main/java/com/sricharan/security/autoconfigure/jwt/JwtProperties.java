package com.sricharan.security.autoconfigure.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for JWT generation and verification.
 * <p>Prefix: {@code security.jwt}
 *
 * <p><strong>IMPORTANT:</strong> Only required when {@code security.auth-mode=INTERNAL} (the default).
 * When using {@code OAUTH2} or {@code KEYCLOAK} mode, these properties are ignored.
 * You MUST set {@code security.jwt.secret} in INTERNAL mode — the application will refuse to start without it.
 */
@ConfigurationProperties(prefix = "security.jwt")
public class JwtProperties {

    /**
     * The HMAC secret key used to sign JWT tokens.
     * <strong>Must be explicitly configured in INTERNAL mode.</strong>
     * Ignored in OAUTH2 and KEYCLOAK modes.
     */
    private String secret;

    /**
     * Access token expiration time in milliseconds.
     * Default: 3600000 (1 hour).
     */
    private long expirationMs = 3600000L;

    /**
     * Refresh token expiration time in milliseconds.
     * Default: 604800000 (7 days).
     */
    private long refreshExpirationMs = 604_800_000L;

    /**
     * The issuer claim ({@code iss}) embedded in generated tokens.
     * Default: {@code spring-security-explainer}.
     */
    private String issuer = "spring-security-explainer";

    /**
     * Validates that the JWT secret is properly configured.
     *
     * <p>Called by {@link JwtService} constructor (INTERNAL mode only).
     * This is intentionally not a {@code @PostConstruct} method to avoid
     * failing in OAUTH2/KEYCLOAK modes where the secret is not required.
     *
     * @throws IllegalStateException if the secret is null or blank
     */
    public void validate() {
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException(
                    "JWT secret is not configured. Set 'security.jwt.secret' in your application properties.");
        }
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public long getExpirationMs() {
        return expirationMs;
    }

    public void setExpirationMs(long expirationMs) {
        this.expirationMs = expirationMs;
    }

    public long getRefreshExpirationMs() {
        return refreshExpirationMs;
    }

    public void setRefreshExpirationMs(long refreshExpirationMs) {
        this.refreshExpirationMs = refreshExpirationMs;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }
}

