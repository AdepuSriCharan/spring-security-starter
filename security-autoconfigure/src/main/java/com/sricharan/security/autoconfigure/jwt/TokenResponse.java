package com.sricharan.security.autoconfigure.jwt;

/**
 * Standard token response returned by the {@code /login} and {@code /refresh} endpoints.
 *
 * <p>This replaces raw {@code Map<String, String>} for type safety and documentation.
 */
public class TokenResponse {

    private final String accessToken;
    private final String refreshToken;
    private final long expiresIn;
    private final String tokenType;

    public TokenResponse(String accessToken, String refreshToken, long expiresIn) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
        this.tokenType = "Bearer";
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public long getExpiresIn() {
        return expiresIn;
    }

    public String getTokenType() {
        return tokenType;
    }
}
