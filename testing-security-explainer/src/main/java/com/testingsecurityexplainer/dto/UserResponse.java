package com.testingsecurityexplainer.dto;

import com.testingsecurityexplainer.model.User;

import java.util.Set;

/**
 * Response payload for a user — never exposes the hashed password.
 */
public class UserResponse {

    private String id;
    private String username;
    private Set<String> roles;
    private Set<String> permissions;

    private UserResponse() {}

    /** Factory — builds a response from a JPA entity. */
    public static UserResponse from(User user) {
        UserResponse r = new UserResponse();
        r.id = user.getId();
        r.username = user.getUsername();
        r.roles = user.getRoles();
        r.permissions = user.getPermissions();
        return r;
    }

    public String getId() { return id; }
    public String getUsername() { return username; }
    public Set<String> getRoles() { return roles; }
    public Set<String> getPermissions() { return permissions; }
}
