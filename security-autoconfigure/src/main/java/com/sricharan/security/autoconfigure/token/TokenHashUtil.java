package com.sricharan.security.autoconfigure.token;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Utility for hashing refresh tokens before storage.
 *
 * <p>Raw refresh tokens must NEVER be persisted. This utility produces a
 * one-way SHA-256 hash that is safe to store in a database or in-memory map.
 */
public final class TokenHashUtil {

    private TokenHashUtil() {
        // Utility class — prevent instantiation
    }

    /**
     * Produces a hex-encoded SHA-256 hash of the given token.
     *
     * @param rawToken The raw refresh token string.
     * @return Lowercase hex-encoded SHA-256 digest.
     */
    public static String sha256(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed by the Java spec — this should never happen
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }
}
