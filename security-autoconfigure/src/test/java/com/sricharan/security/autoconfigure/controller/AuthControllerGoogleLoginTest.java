package com.sricharan.security.autoconfigure.controller;

import com.sricharan.security.autoconfigure.google.GoogleIdentityTokenVerifier;
import com.sricharan.security.autoconfigure.jwt.JwtService;
import com.sricharan.security.autoconfigure.jwt.TokenResponse;
import com.sricharan.security.autoconfigure.observability.SecurityEventRecorder;
import com.sricharan.security.core.account.ExternalIdentityAccountLinker;
import com.sricharan.security.core.account.UserAccount;
import com.sricharan.security.core.account.UserAccountProvider;
import com.sricharan.security.core.identity.ExternalIdentityProfile;
import com.sricharan.security.core.token.RefreshTokenStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthControllerGoogleLoginTest {

    private ObjectProvider<UserAccountProvider> userAccountProviderRef;
    private ObjectProvider<ExternalIdentityAccountLinker> externalIdentityAccountLinkerRef;
    private ObjectProvider<GoogleIdentityTokenVerifier> googleIdentityTokenVerifierRef;
    private PasswordEncoder passwordEncoder;
    private JwtService jwtService;
    private RefreshTokenStore refreshTokenStore;
    private SecurityEventRecorder securityEventRecorder;
    private AuthController controller;

    @BeforeEach
    void setUp() {
        userAccountProviderRef = mock(ObjectProvider.class);
        externalIdentityAccountLinkerRef = mock(ObjectProvider.class);
        googleIdentityTokenVerifierRef = mock(ObjectProvider.class);
        passwordEncoder = mock(PasswordEncoder.class);
        jwtService = mock(JwtService.class);
        refreshTokenStore = mock(RefreshTokenStore.class);
        securityEventRecorder = mock(SecurityEventRecorder.class);

        controller = new AuthController(
                userAccountProviderRef,
                passwordEncoder,
                jwtService,
                refreshTokenStore,
                securityEventRecorder,
                externalIdentityAccountLinkerRef,
                googleIdentityTokenVerifierRef);
    }

    @Test
    void googleLoginIssuesInternalTokenPair() {
        GoogleIdentityTokenVerifier verifier = mock(GoogleIdentityTokenVerifier.class);
        ExternalIdentityAccountLinker linker = mock(ExternalIdentityAccountLinker.class);
        UserAccount user = mock(UserAccount.class);

        when(googleIdentityTokenVerifierRef.getIfAvailable()).thenReturn(verifier);
        when(externalIdentityAccountLinkerRef.getIfAvailable()).thenReturn(linker);
        when(verifier.verify("google-id-token")).thenReturn(new ExternalIdentityProfile(
                "google",
                "sub-123",
                "user@example.com",
                true,
                "Google User",
                Map.of()));
        when(linker.createOrLink(any())).thenReturn(user);
        when(user.getId()).thenReturn("user-1");
        when(user.getUsername()).thenReturn("user@example.com");
        when(user.getPassword()).thenReturn("n/a");
        when(user.getRoles()).thenReturn(java.util.Set.of("DEFAULT"));
        when(user.getPermissions()).thenReturn(java.util.Set.of());
        when(jwtService.generateToken(user)).thenReturn("access-token");
        when(jwtService.generateRefreshToken(user)).thenReturn("refresh-token");
        when(jwtService.getExpirationMs()).thenReturn(3600000L);
        when(jwtService.getRefreshExpirationMs()).thenReturn(604800000L);

        AuthController.GoogleLoginRequest request = new AuthController.GoogleLoginRequest();
        request.setIdToken("google-id-token");

        var response = controller.googleLogin(request);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        TokenResponse body = (TokenResponse) response.getBody();
        assertThat(body.getAccessToken()).isEqualTo("access-token");
        assertThat(body.getRefreshToken()).isEqualTo("refresh-token");
    }

    @Test
    void googleLoginReturnsBadRequestWhenTokenMissing() {
        AuthController.GoogleLoginRequest request = new AuthController.GoogleLoginRequest();

        var response = controller.googleLogin(request);

        assertThat(response.getStatusCode().value()).isEqualTo(400);
    }
}
