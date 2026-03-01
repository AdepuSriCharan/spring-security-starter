package com.testingsecurityexplainer.service;

import com.sricharan.security.core.account.UserAccount;
import com.sricharan.security.core.account.UserAccountProvider;
import com.testingsecurityexplainer.model.User;
import com.testingsecurityexplainer.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.Set;

/**
 * DB-backed UserAccountProvider — the ONLY thing a developer needs to
 * implement to plug the security-starter into their application.
 */
@Service
public class UserService implements UserAccountProvider {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<UserAccount> findByUsername(String username) {
        return userRepository.findByUsername(username).map(u -> u);
    }

    /**
     * Registers a new user, hashing the password before saving.
     */
    public User register(String username, String rawPassword, Set<String> roles, Set<String> permissions) {
        String hashed = passwordEncoder.encode(rawPassword);
        User user = new User(username, hashed, roles, permissions);
        return userRepository.save(user);
    }
}
