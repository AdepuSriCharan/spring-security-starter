package com.testingsecurityexplainer.controller;

import com.testingsecurityexplainer.dto.RegisterRequest;
import com.testingsecurityexplainer.model.User;
import com.testingsecurityexplainer.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.Set;

/**
 * Registration endpoint — allows creating users that persist in PostgreSQL.
 * This endpoint is open (no auth required) so you can register during testing.
 */
@RestController
@RequestMapping("/register")
public class RegistrationController {

    private final UserService userService;

    public RegistrationController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping
    public ResponseEntity<Map<String, Object>> register(@RequestBody RegisterRequest request) {
        // Enforce USER role for all new registrations (ignore client request for roles)
        Set<String> roles = Set.of("USER");

        Set<String> permissions = (request.getPermissions() != null)
                ? request.getPermissions()
                : Set.of();

        User saved = userService.register(
                request.getUsername(),
                request.getPassword(),
                roles,
                permissions
        );

        return ResponseEntity.ok(Map.of(
                "message", "User registered successfully",
                "id", saved.getId(),
                "username", saved.getUsername(),
                "roles", saved.getRoles()
        ));
    }
}
