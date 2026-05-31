package com.sricharan.security.autoconfigure.google;

import com.sricharan.security.autoconfigure.config.SecurityProperties;
import com.sricharan.security.core.identity.ExternalIdentityProfile;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Verifies Google ID tokens and normalizes them into an external identity profile.
 */
public class GoogleIdentityTokenVerifier {

    private final SecurityProperties.Google properties;
    private final JwtDecoder jwtDecoder;

    public GoogleIdentityTokenVerifier(SecurityProperties properties) {
        this.properties = properties.getGoogle();
        List<String> allowedClientIds = normalizeClientIds(this.properties.getClientIds());
        if (allowedClientIds.isEmpty()) {
            throw new IllegalStateException(
                    "security.google.client-ids must contain at least one client id when Google sign-in is enabled.");
        }

        NimbusJwtDecoder decoder = NimbusJwtDecoder
                .withIssuerLocation(this.properties.getIssuerUri())
                .build();

        OAuth2TokenValidator<Jwt> issuerValidator = JwtValidators.createDefaultWithIssuer(this.properties.getIssuerUri());
        OAuth2TokenValidator<Jwt> audienceValidator = audienceValidator(allowedClientIds);

        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(issuerValidator, audienceValidator));
        this.jwtDecoder = decoder;
    }

    static OAuth2TokenValidator<Jwt> audienceValidator(List<String> allowedClientIds) {
        List<String> normalizedAllowedClientIds = normalizeClientIds(allowedClientIds);
        return jwt -> {
            List<String> tokenAudiences = jwt.getAudience() == null ? List.of() : jwt.getAudience();
            return tokenAudiences.stream().anyMatch(normalizedAllowedClientIds::contains)
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(
                        new OAuth2Error("invalid_token", "Google token audience does not match any configured client id.", null));
        };
    }

    public ExternalIdentityProfile verify(String idToken) {
        if (idToken == null || idToken.isBlank()) {
            throw new IllegalArgumentException("Google ID token is required.");
        }

        try {
            Jwt jwt = jwtDecoder.decode(idToken);
            String subject = requiredClaim(jwt, "sub");
            String email = jwt.getClaimAsString("email");
            Boolean emailVerified = jwt.getClaimAsBoolean("email_verified");
            String displayName = firstNonBlank(
                    jwt.getClaimAsString("name"),
                    jwt.getClaimAsString("given_name"),
                    jwt.getClaimAsString("email"),
                    subject);

            Map<String, Object> claims = new HashMap<>(jwt.getClaims());
            return new ExternalIdentityProfile(
                    "google",
                    subject,
                    email,
                    Boolean.TRUE.equals(emailVerified),
                    displayName,
                    claims);
        } catch (JwtException ex) {
            throw new IllegalArgumentException("Invalid Google ID token.", ex);
        }
    }

    private static String requiredClaim(Jwt jwt, String claim) {
        String value = jwt.getClaimAsString(claim);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Google ID token is missing required claim: " + claim);
        }
        return value;
    }

    private static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    private static List<String> normalizeClientIds(List<String> clientIds) {
        if (clientIds == null) {
            return List.of();
        }
        return clientIds.stream()
                .filter(StringUtils::hasText)
                .map(String::trim)
                .distinct()
                .toList();
    }
}
