package com.sricharan.security.autoconfigure.google;

import com.sricharan.security.autoconfigure.config.SecurityProperties;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThat;

class GoogleIdentityTokenVerifierTest {

    @Test
    void constructorRejectsMissingClientIds() {
        SecurityProperties properties = new SecurityProperties();
        properties.getGoogle().setEnabled(true);
        properties.getGoogle().setClientIds(List.of());

        assertThatThrownBy(() -> new GoogleIdentityTokenVerifier(properties))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("security.google.client-ids");
    }

    @Test
    void audienceValidatorAcceptsAnyConfiguredClientId() {
        Jwt jwt = buildJwt("android-client-id");

        OAuth2TokenValidatorResult result = GoogleIdentityTokenVerifier
                .audienceValidator(List.of("web-client-id", "android-client-id"))
                .validate(jwt);

        assertThat(result.hasErrors()).isFalse();
    }

    @Test
    void audienceValidatorRejectsUnknownAudience() {
        Jwt jwt = buildJwt("unknown-client-id");

        OAuth2TokenValidatorResult result = GoogleIdentityTokenVerifier
                .audienceValidator(List.of("web-client-id", "android-client-id"))
                .validate(jwt);

        assertThat(result.hasErrors()).isTrue();
    }

    private static Jwt buildJwt(String audience) {
        return Jwt.withTokenValue("token")
                .header("alg", "none")
                .issuer("https://accounts.google.com")
                .subject("subject-123")
                .claim("aud", List.of(audience))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .claim("sub", "subject-123")
                .build();
    }
}
