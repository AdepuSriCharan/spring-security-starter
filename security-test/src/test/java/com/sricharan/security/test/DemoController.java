package com.sricharan.security.test;

import com.sricharan.security.core.annotation.RequireOwner;
import com.sricharan.security.core.annotation.RequirePermission;
import com.sricharan.security.core.annotation.RequireRole;
import com.sricharan.security.core.context.SecurityUserContext;
import com.sricharan.security.core.user.AuthenticatedUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Demo controller used for integration testing.
 *
 * <p>Each endpoint demonstrates a different authorization scenario.
 */
@RestController
public class DemoController {

    @GetMapping("/public")
    public Map<String, Object> publicEndpoint() {
        return Map.of(
                "message", "This is a public endpoint",
                "secured", false
        );
    }

    @GetMapping("/admin")
    @RequireRole("ADMIN")
    public Map<String, Object> adminEndpoint() {
        AuthenticatedUser user = SecurityUserContext.getCurrentUser();
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("message", "Welcome to the admin area");
        response.put("user", user.getUsername());
        response.put("roles", user.getRoles());
        return response;
    }

    @GetMapping("/user")
    @RequireRole("USER")
    public Map<String, Object> userEndpoint() {
        AuthenticatedUser user = SecurityUserContext.getCurrentUser();
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("message", "User profile area");
        response.put("user", user.getUsername());
        response.put("roles", user.getRoles());
        return response;
    }

    @GetMapping("/multi-role")
    @RequireRole({"ADMIN", "MANAGER"})
    public Map<String, Object> multiRoleEndpoint() {
        AuthenticatedUser user = SecurityUserContext.getCurrentUser();
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("message", "Accessible by ADMIN or MANAGER");
        response.put("user", user.getUsername());
        return response;
    }

    @GetMapping("/with-permission")
    @RequirePermission("donor:create")
    public Map<String, Object> permissionEndpoint() {
        AuthenticatedUser user = SecurityUserContext.getCurrentUser();
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("message", "Permission-based endpoint");
        response.put("user", user.getUsername());
        response.put("permissions", user.getPermissions());
        return response;
    }

    @GetMapping("/users/{userId}/profile")
    @RequireOwner("#userId")
    public Map<String, Object> userProfileEndpoint(@PathVariable String userId) {
        AuthenticatedUser user = SecurityUserContext.getCurrentUser();
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("message", "This is the user's private profile");
        response.put("user", user.getUsername());
        response.put("userId", user.getUserId());
        return response;
    }
}
