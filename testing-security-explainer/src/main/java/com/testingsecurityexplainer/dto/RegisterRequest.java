package com.testingsecurityexplainer.dto;

import java.util.Set;

/**
 * Request body for the POST /register endpoint.
 */
public class RegisterRequest {
    private String username;
    private String password;
    private Set<String> roles;
    private Set<String> permissions;

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public Set<String> getRoles() { return roles; }
    public void setRoles(Set<String> roles) { this.roles = roles; }

    public Set<String> getPermissions() { return permissions; }
    public void setPermissions(Set<String> permissions) { this.permissions = permissions; }
}
