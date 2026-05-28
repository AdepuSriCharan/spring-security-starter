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
    private String authProvider;
    private String externalSubject;
    private String externalEmail;
    private Boolean externalEmailVerified;

    private UserResponse() {}

    /** Factory — builds a response from a JPA entity. */
    public static UserResponse from(User user) {
        UserResponse r = new UserResponse();
        r.id = user.getId();
        r.username = user.getUsername();
        r.roles = user.getRoles();
        r.permissions = user.getPermissions();
        r.authProvider = user.getAuthProvider();
        r.externalSubject = user.getExternalSubject();
        r.externalEmail = user.getExternalEmail();
        r.externalEmailVerified = user.getExternalEmailVerified();
        return r;
    }

    public String getId() { return id; }
    public String getUsername() { return username; }
    public Set<String> getRoles() { return roles; }
    public Set<String> getPermissions() { return permissions; }
    public String getAuthProvider() { return authProvider; }
    public String getExternalSubject() { return externalSubject; }
    public String getExternalEmail() { return externalEmail; }
    public Boolean getExternalEmailVerified() { return externalEmailVerified; }
}
