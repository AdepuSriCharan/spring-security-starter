package com.testingsecurityexplainer.controller;

import com.sricharan.security.core.annotation.RequirePermission;
import com.sricharan.security.core.annotation.RequireRole;
import com.sricharan.security.core.annotation.RequireOwner;
import com.sricharan.security.core.context.SecurityUserContext;
import com.sricharan.security.core.user.AuthenticatedUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Demo controller showing how to use the security framework's annotations.
 */
@RestController
public class DemoController {

    @GetMapping("/public")
    public Map<String, String> publicEndpoint() {
        return Map.of("message", "This is a public endpoint accessible by anyone.");
    }

    @GetMapping("/user")
    @RequireRole("USER")
    public Map<String, Object> userEndpoint() {
        AuthenticatedUser user = SecurityUserContext.getCurrentUser();
        return Map.of(
                "message", "Welcome, regular user!",
                "your_context", user
        );
    }

    @GetMapping("/admin")
    @RequireRole("ADMIN")
    public Map<String, String> adminEndpoint() {
        return Map.of("message", "Greetings, Admin! You have accessed the high-security bridge.");
    }

    @GetMapping("/audit")
    @RequirePermission("system:write")
    public Map<String, String> auditEndpoint() {
        return Map.of("message", "You have permission to perform system writes (auditing).");
    }

    /**
     * Demonstrates @RequireOwner.
     * Access is granted if the {userId} in the URL matches the logged-in user's ID.
     */
    @GetMapping("/profile/{userId}")
    @RequireOwner("#userId")
    public Map<String, String> getProfile(@PathVariable String userId) {
        return Map.of("message", "You are viewing your own private profile (ID: " + userId + ").");
    }
}
