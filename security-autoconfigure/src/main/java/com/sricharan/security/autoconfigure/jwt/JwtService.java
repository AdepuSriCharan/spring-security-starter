package com.sricharan.security.autoconfigure.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.sricharan.security.core.account.UserAccount;

import java.time.Instant;
import java.util.ArrayList;
import java.util.UUID;

/**
 * Service responsible for generating, parsing, and refreshing JWTs
 * using the com.auth0:java-jwt library.
 */
public class JwtService {

    private static final String CLAIM_TYPE = "type";
    private static final String TYPE_ACCESS = "access";
    private static final String TYPE_REFRESH = "refresh";

    private final JwtProperties properties;
    private final Algorithm algorithm;
    private final JWTVerifier accessVerifier;
    private final JWTVerifier refreshVerifier;

    public JwtService(JwtProperties properties) {
        properties.validate();  // fail fast — only reached in INTERNAL mode
        this.properties = properties;
        this.algorithm = Algorithm.HMAC256(properties.getSecret());
        this.accessVerifier = JWT.require(this.algorithm)
                .withIssuer(properties.getIssuer())
                .withClaim(CLAIM_TYPE, TYPE_ACCESS)
                .build();
        this.refreshVerifier = JWT.require(this.algorithm)
                .withIssuer(properties.getIssuer())
                .withClaim(CLAIM_TYPE, TYPE_REFRESH)
                .build();
    }

    /**
     * Generates a short-lived access token storing the user's ID, username, roles, and permissions.
     */
    public String generateToken(UserAccount userAccount) {
        Instant now = Instant.now();
        Instant validity = now.plusMillis(properties.getExpirationMs());

        return JWT.create()
                .withIssuer(properties.getIssuer())
                .withSubject(userAccount.getUsername())
                .withJWTId(UUID.randomUUID().toString())
                .withClaim("userId", userAccount.getId())
                .withClaim("roles", new ArrayList<>(userAccount.getRoles()))
                .withClaim("permissions", new ArrayList<>(userAccount.getPermissions()))
                .withClaim(CLAIM_TYPE, TYPE_ACCESS)
                .withIssuedAt(now)
                .withExpiresAt(validity)
                .sign(algorithm);
    }

    /**
     * Generates a long-lived refresh token with minimal claims (subject only).
     *
     * <p>Refresh tokens should NOT contain roles/permissions — they are only
     * used to obtain a new access token pair, at which point fresh roles are loaded.
     */
    public String generateRefreshToken(UserAccount userAccount) {
        Instant now = Instant.now();
        Instant validity = now.plusMillis(properties.getRefreshExpirationMs());

        return JWT.create()
                .withIssuer(properties.getIssuer())
                .withSubject(userAccount.getUsername())
                .withJWTId(UUID.randomUUID().toString())
                .withClaim(CLAIM_TYPE, TYPE_REFRESH)
                .withIssuedAt(now)
                .withExpiresAt(validity)
                .sign(algorithm);
    }

    /**
     * Verifies an access token and returns the parsed contents.
     *
     * @param token The raw Bearer token (without the 'Bearer ' prefix).
     * @return DecodedJWT if valid.
     * @throws JWTVerificationException if the token is tampered with, expired, or invalid.
     */
    public DecodedJWT verifyToken(String token) throws JWTVerificationException {
        return accessVerifier.verify(token);
    }

    /**
     * Verifies a refresh token and returns the username (subject).
     *
     * @param refreshToken The raw refresh token string.
     * @return The username embedded in the refresh token.
     * @throws JWTVerificationException if the token is invalid or expired.
     */
    public String verifyRefreshToken(String refreshToken) throws JWTVerificationException {
        DecodedJWT decoded = refreshVerifier.verify(refreshToken);
        return decoded.getSubject();
    }

    /**
     * Returns the access token expiration time in milliseconds (for including in responses).
     */
    public long getExpirationMs() {
        return properties.getExpirationMs();
    }

    /**
     * Returns the refresh token expiration time in milliseconds (for storage tracking).
     */
    public long getRefreshExpirationMs() {
        return properties.getRefreshExpirationMs();
    }
}

