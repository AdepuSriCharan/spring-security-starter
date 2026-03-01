package com.sricharan.security.core.user;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * The universal identity object for the security layer.
 *
 * <p>Every authentication source (JWT, Keycloak, Spring Security, OAuth2)
 * is converted into this single representation via an {@code AuthenticationAdapter}.
 *
 * <p>This is the object that authorization decisions are made against.
 */
public class AuthenticatedUser {

    private final String username;
    private final String userId;
    private final Set<String> roles;
    private final Set<String> permissions;
    private final Map<String, Object> attributes;

    private AuthenticatedUser(Builder builder) {
        this.username = builder.username;
        this.userId = builder.userId != null ? builder.userId : builder.username;
        this.roles = Collections.unmodifiableSet(builder.roles);
        this.permissions = Collections.unmodifiableSet(builder.permissions);
        this.attributes = Collections.unmodifiableMap(builder.attributes);
    }

    // ── Getters ─────────────────────────────────────────────

    public String getUsername() {
        return username;
    }

    public String getUserId() {
        return userId;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public Set<String> getPermissions() {
        return permissions;
    }

    public Map<String, Object> getAttributes() {
        return attributes;
    }

    /**
     * Convenience check — does this user hold the given role?
     */
    public boolean hasRole(String role) {
        return roles.contains(role);
    }

    /**
     * Convenience check — does this user hold the given permission?
     */
    public boolean hasPermission(String permission) {
        return permissions.contains(permission);
    }

    /**
     * Retrieve a typed attribute.
     */
    @SuppressWarnings("unchecked")
    public <T> T getAttribute(String key) {
        return (T) attributes.get(key);
    }

    @Override
    public String toString() {
        return "AuthenticatedUser{" +
                "username='" + username + '\'' +
                ", userId='" + userId + '\'' +
                ", roles=" + roles +
                ", permissions=" + permissions +
                '}';
    }

    // ── Builder ─────────────────────────────────────────────

    public static Builder builder(String username) {
        return new Builder(username);
    }

    public static class Builder {

        private final String username;
        private String userId;
        private Set<String> roles = Collections.emptySet();
        private Set<String> permissions = Collections.emptySet();
        private Map<String, Object> attributes = Collections.emptyMap();

        private Builder(String username) {
            if (username == null || username.isBlank()) {
                throw new IllegalArgumentException("Username must not be null or blank");
            }
            this.username = username;
        }

        public Builder userId(String userId) {
            this.userId = userId;
            return this;
        }

        public Builder roles(Set<String> roles) {
            this.roles = roles != null ? roles : Collections.emptySet();
            return this;
        }

        public Builder permissions(Set<String> permissions) {
            this.permissions = permissions != null ? permissions : Collections.emptySet();
            return this;
        }

        public Builder attributes(Map<String, Object> attributes) {
            this.attributes = attributes != null ? attributes : Collections.emptyMap();
            return this;
        }

        public AuthenticatedUser build() {
            return new AuthenticatedUser(this);
        }
    }
}
