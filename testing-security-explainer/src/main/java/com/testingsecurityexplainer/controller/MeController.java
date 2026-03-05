package com.testingsecurityexplainer.controller;

import com.sricharan.security.core.annotation.RequireOwner;
import com.sricharan.security.core.annotation.RequireRole;
import com.sricharan.security.core.context.SecurityUserContext;
import com.sricharan.security.core.user.AuthenticatedUser;
import com.testingsecurityexplainer.dto.UserResponse;
import com.testingsecurityexplainer.service.UserService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Endpoints related to the currently authenticated user.
 *
 * <p>GET /me       — any authenticated user can inspect their own context
 * <p>GET /public   — completely open, no token needed
 * <p>GET /users/{id} — fetches another user's profile; ADMIN only
 */
@RestController
public class MeController {

    private final UserService userService;

    public MeController(UserService userService) {
        this.userService = userService;
    }

    /** Open endpoint — verifies the server is up without a token. */
    @GetMapping("/public")
    public Map<String, String> publicEndpoint() {
        return Map.of("message", "Public endpoint — no authentication required.");
    }

    /**
     * Returns the full {@link AuthenticatedUser} for the caller.
     * Demonstrates that the security context is populated correctly after login.
     */
    @GetMapping("/me")
    public AuthenticatedUser me() {
        return SecurityUserContext.requireCurrentUser();
    }

    /**
     * Fetches any user's profile — ADMIN only.
     * Exercises @RequireRole on an endpoint that is NOT about ownership.
     */
    @GetMapping("/users/{id}")
    @RequireRole("ADMIN")
    public UserResponse getUserById(@PathVariable String id) {
        return userService.findById(id);
    }

    /**
     * Demonstrates {@code @RequireOwner} — the caller may only view their own profile.
     *
     * <p>The SpEL expression {@code "#userId"} refers to the {@code userId} method
     * parameter. The aspect compares it to {@code AuthenticatedUser#getUserId()}.
     * Any attempt to access another user's profile returns 403.
     */
    @GetMapping("/profile/{userId}")
    @RequireOwner("#userId")
    public UserResponse getOwnProfile(@PathVariable String userId) {
        return userService.findById(userId);
    }
}

