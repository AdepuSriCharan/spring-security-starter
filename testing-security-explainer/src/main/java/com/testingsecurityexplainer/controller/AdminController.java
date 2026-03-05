package com.testingsecurityexplainer.controller;

import com.sricharan.security.core.annotation.RequireRole;
import com.testingsecurityexplainer.dto.UserResponse;
import com.testingsecurityexplainer.service.UserService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Admin-only endpoints.
 *
 * <p>Every method here requires the {@code ADMIN} role — demonstrating that
 * {@code @RequireRole} can protect an entire controller's worth of endpoints.
 */
@RestController
@RequestMapping("/admin")
public class AdminController {

    private final UserService userService;

    public AdminController(UserService userService) {
        this.userService = userService;
    }

    /**
     * Lists every registered user (id, username, roles, permissions).
     * Passwords are never included — the service returns {@link UserResponse} DTOs.
     */
    @GetMapping("/users")
    @RequireRole("ADMIN")
    public List<UserResponse> getAllUsers() {
        return userService.findAll();
    }
}
