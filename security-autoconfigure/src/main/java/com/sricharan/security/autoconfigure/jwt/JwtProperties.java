package com.sricharan.security.autoconfigure.jwt;

import jakarta.annotation.PostConstruct;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for JWT generation and verification.
 * <p>Prefix: {@code security.jwt}
 *
 * <p><strong>IMPORTANT:</strong> You MUST set {@code security.jwt.secret} in your
 * application properties. The application will refuse to start without it.
 */
@ConfigurationProperties(prefix = "security.jwt")
public class JwtProperties {

    private static final String INSECURE_DEFAULT = "default-insecure-secret-change-me-immediately";

    /**
     * The secret key used to sign the JWT tokens.
     * <strong>Must be explicitly configured — no default provided.</strong>
     */
    private String secret;

    /**
     * Token expiration time in milliseconds.
     * Default: 3600000ms (1 Hour)
     */
    private long expirationMs = 3600000L;

    /**
     * Refresh token expiration time in milliseconds.
     * Default: 604800000ms (7 Days)
     */
    private long refreshExpirationMs = 604_800_000L;

    /**
     * The issuer of the token.
     * Default: spring-security-explainer
     */
    private String issuer = "spring-security-explainer";

    @PostConstruct
    public void validate() {
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException(
                    "JWT secret is not configured. Set 'security.jwt.secret' in your application properties.");
        }
        if (INSECURE_DEFAULT.equals(secret)) {
            throw new IllegalStateException(
                    "JWT secret is set to the insecure default. " +
                    "You MUST provide a strong, unique secret via 'security.jwt.secret'.");
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

