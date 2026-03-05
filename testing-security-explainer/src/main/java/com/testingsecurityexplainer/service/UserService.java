package com.testingsecurityexplainer.service;

import com.sricharan.security.core.account.UserAccount;
import com.sricharan.security.core.account.UserAccountProvider;
import com.testingsecurityexplainer.dto.UserResponse;
import com.testingsecurityexplainer.model.User;
import com.testingsecurityexplainer.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Manages user accounts.
 *
 * <p>Implements {@link UserAccountProvider} so the security-starter can look up
 * users by username during the /login flow — the only contract the library needs.
 *
 * <p>Also exposes registration and admin-facing listing methods used by controllers.
 */
@Service
public class UserService implements UserAccountProvider {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // ── UserAccountProvider (required by security-starter) ───────────────────

    @Override
    public Optional<UserAccount> findByUsername(String username) {
        return userRepository.findByUsername(username).map(u -> u);
    }

    // ── Registration ─────────────────────────────────────────────────────────

    /**
     * Registers a standard user with the {@code USER} role.
     * Throws {@link IllegalArgumentException} if the username is already taken.
     */
    @Transactional
    public UserResponse registerUser(String username, String rawPassword) {
        ensureUsernameAvailable(username);
        User user = new User(username, passwordEncoder.encode(rawPassword),
                Set.of("USER"), Set.of());
        return UserResponse.from(userRepository.save(user));
    }

    /**
     * Registers an admin user with {@code USER} + {@code ADMIN} roles and
     * the {@code post:delete} permission so they can exercise @RequirePermission.
     * Throws {@link IllegalArgumentException} if the username is already taken.
     */
    @Transactional
    public UserResponse registerAdmin(String username, String rawPassword) {
        ensureUsernameAvailable(username);
        User user = new User(username, passwordEncoder.encode(rawPassword),
                Set.of("USER", "ADMIN"), Set.of("post:delete"));
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

