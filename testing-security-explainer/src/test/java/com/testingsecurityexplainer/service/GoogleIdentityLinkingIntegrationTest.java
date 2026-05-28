package com.testingsecurityexplainer.service;

import com.sricharan.security.core.identity.ExternalIdentityProfile;
import com.testingsecurityexplainer.model.User;
import com.testingsecurityexplainer.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class GoogleIdentityLinkingIntegrationTest {

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    @Test
    @Transactional
    void createOrLinkGoogleIdentityCreatesLocalUser() {
        ExternalIdentityProfile profile = new ExternalIdentityProfile(
                "google",
                "google-sub-123",
                "google-user@example.com",
                true,
                "Google User",
                Map.of("hd", "example.com"));

        userService.createOrLink(profile);

        User saved = userRepository.findByExternalSubject("google-sub-123")
                .orElseThrow();

        assertThat(saved.getUsername()).isEqualTo("google-user@example.com");
        assertThat(saved.getAuthProvider()).isEqualTo("GOOGLE");
        assertThat(saved.getExternalEmail()).isEqualTo("google-user@example.com");
        assertThat(saved.getExternalEmailVerified()).isTrue();
    }

    @Test
    @Transactional
    void createOrLinkGoogleIdentityLinksExistingLocalUserByEmail() {
        userService.registerUser("existing@example.com", "Pass@123");
        User existing = userRepository.findByUsername("existing@example.com").orElseThrow();

        ExternalIdentityProfile profile = new ExternalIdentityProfile(
                "google",
                "google-sub-456",
                "existing@example.com",
                true,
                "Existing User",
                Map.of());

        userService.createOrLink(profile);

        User linked = userRepository.findByExternalSubject("google-sub-456").orElseThrow();
        assertThat(linked.getId()).isEqualTo(existing.getId());
        assertThat(linked.getAuthProvider()).isEqualTo("LINKED");
        assertThat(linked.getExternalSubject()).isEqualTo("google-sub-456");
    }
}
