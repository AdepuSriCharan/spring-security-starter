package com.testingsecurityexplainer.service;

import com.sricharan.security.core.account.UserAccount;
import com.sricharan.security.core.account.ExternalIdentityAccountLinker;
import com.sricharan.security.core.account.UserAccountProvider;
import com.sricharan.security.core.identity.ExternalIdentityProfile;
import com.testingsecurityexplainer.dto.UserResponse;
import com.testingsecurityexplainer.enums.RoleType;
import com.testingsecurityexplainer.model.Role;
import com.testingsecurityexplainer.model.User;
import com.testingsecurityexplainer.repository.RoleRepository;
import com.testingsecurityexplainer.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Manages user accounts.
 *
 * <p>Implements {@link UserAccountProvider} so the security-starter can look up
 * users by username during the /login flow — the only contract the library needs.
 *
 * <p>Also exposes registration and admin-facing listing methods used by controllers.
 */
@Service
public class UserService implements UserAccountProvider, ExternalIdentityAccountLinker {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, 
                       RoleRepository roleRepository,
                       PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // ── UserAccountProvider (required by security-starter) ───────────────────

    @Override
    public Optional<UserAccount> findByUsername(String username) {
        return userRepository.findByUsername(username).map(u -> u);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<UserAccount> findByExternalIdentity(String provider, String subject) {
        if (!"google".equalsIgnoreCase(provider) || subject == null || subject.isBlank()) {
            return Optional.empty();
        }
        return userRepository.findByExternalSubject(subject).map(u -> u);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<UserAccount> findByEmail(String email) {
        if (email == null || email.isBlank()) {
            return Optional.empty();
        }
        return userRepository.findByExternalEmail(email)
                .map(u -> (UserAccount) u)
                .or(() -> userRepository.findByUsername(email).map(u -> (UserAccount) u));
    }

    @Override
    @Transactional
    public UserAccount createOrLink(ExternalIdentityProfile profile) {
        if (profile == null) {
            throw new IllegalArgumentException("External identity profile is required");
        }
        if (!"google".equalsIgnoreCase(profile.provider())) {
            throw new IllegalArgumentException("Unsupported external identity provider: " + profile.provider());
        }

        Optional<User> bySubject = userRepository.findByExternalSubject(profile.subject());
        if (bySubject.isPresent()) {
            return bySubject.get();
        }

        Optional<User> byEmail = Optional.empty();
        if (profile.email() != null && !profile.email().isBlank()) {
            byEmail = userRepository.findByExternalEmail(profile.email())
                    .or(() -> userRepository.findByUsername(profile.email()));
        }

        if (byEmail.isPresent()) {
            User existing = byEmail.get();
            existing.setAuthProvider("LINKED");
            existing.setExternalSubject(profile.subject());
            existing.setExternalEmail(profile.email());
            existing.setExternalEmailVerified(profile.emailVerified());
            return userRepository.save(existing);
        }

        Role defaultRole = roleRepository.findByName(RoleType.DEFAULT)
                .orElseThrow(() -> new IllegalStateException("DEFAULT role not found"));

        String username = profile.email();
        if (username == null || username.isBlank()) {
            username = "google_" + profile.subject();
        }

        User created = new User(
                username,
                passwordEncoder.encode(UUID.randomUUID().toString()),
                Set.of(defaultRole),
                Set.of(),
                "GOOGLE",
                profile.subject(),
                profile.email(),
                profile.emailVerified());
        return userRepository.save(created);
    }

    // ── Registration ─────────────────────────────────────────────────────────

    /**
     * Registers a standard user with the {@code DEFAULT} role.
     * Throws {@link IllegalArgumentException} if the username is already taken.
     */
    @Transactional
    public UserResponse registerUser(String username, String rawPassword) {
        ensureUsernameAvailable(username);
        
        Role defaultRole = roleRepository.findByName(RoleType.DEFAULT)
                .orElseThrow(() -> new IllegalStateException("DEFAULT role not found"));
                
        User user = new User(username, passwordEncoder.encode(rawPassword),
                Set.of(defaultRole), Set.of());
        return UserResponse.from(userRepository.save(user));
    }

    /**
     * Registers an admin user with {@code DEFAULT} + {@code ADMIN} roles and
     * the {@code post:delete} permission so they can exercise @RequirePermission.
     * Throws {@link IllegalArgumentException} if the username is already taken.
     */
    @Transactional
    public UserResponse registerAdmin(String username, String rawPassword) {
        ensureUsernameAvailable(username);
        
        Role defaultRole = roleRepository.findByName(RoleType.DEFAULT)
                .orElseThrow(() -> new IllegalStateException("DEFAULT role not found"));
        Role adminRole = roleRepository.findByName(RoleType.ADMIN)
                .orElseThrow(() -> new IllegalStateException("ADMIN role not found"));
                
        User user = new User(username, passwordEncoder.encode(rawPassword),
                Set.of(defaultRole, adminRole), Set.of("post:delete"));
        return UserResponse.from(userRepository.save(user));
    }

    // ── Admin queries ─────────────────────────────────────────────────────────

    /** Returns all registered users. Intended for ADMIN-only endpoints. */
    @Transactional(readOnly = true)
    public List<UserResponse> findAll() {
        return userRepository.findAll().stream()
                .map(UserResponse::from)
                .toList();
    }

    /** Looks up a single user by ID. Throws if not found. */
    @Transactional(readOnly = true)
    public UserResponse findById(String id) {
        return userRepository.findById(id)
                .map(UserResponse::from)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + id));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void ensureUsernameAvailable(String username) {
        if (userRepository.findByUsername(username).isPresent()) {
            throw new IllegalArgumentException("Username already taken: " + username);
        }
    }
}
