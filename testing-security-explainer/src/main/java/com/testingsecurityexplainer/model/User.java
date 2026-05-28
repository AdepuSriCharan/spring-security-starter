package com.testingsecurityexplainer.model;

import com.sricharan.security.core.account.UserAccount;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * JPA entity that represents a user stored in the database.
 * Implements UserAccount so it can be used directly with the security framework.
 */
@Entity
@Table(name = "users")
@Getter
@Setter
public class User implements UserAccount {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(name = "auth_provider")
    private String authProvider = "LOCAL";

    @Column(name = "external_subject", unique = true)
    private String externalSubject;

    @Column(name = "external_email")
    private String externalEmail;

    @Column(name = "external_email_verified")
    private Boolean externalEmailVerified = false;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "user_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_permissions", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "permission")
    private Set<String> permissions;

    // Required by JPA
    protected User() {}

    public User(String username, String password, Set<Role> roles, Set<String> permissions) {
        this.username = username;
        this.password = password;
        this.roles = roles == null ? new HashSet<>() : new HashSet<>(roles);
        this.permissions = permissions == null ? new HashSet<>() : new HashSet<>(permissions);
    }

    public User(
            String username,
            String password,
            Set<Role> roles,
            Set<String> permissions,
            String authProvider,
            String externalSubject,
            String externalEmail,
            Boolean externalEmailVerified) {
        this.username = username;
        this.password = password;
        this.roles = roles == null ? new HashSet<>() : new HashSet<>(roles);
        this.permissions = permissions == null ? new HashSet<>() : new HashSet<>(permissions);
        this.authProvider = authProvider;
        this.externalSubject = externalSubject;
        this.externalEmail = externalEmail;
        this.externalEmailVerified = externalEmailVerified;
    }

    @Override public String getId() { return id; }
    @Override public String getUsername() { return username; }
    @Override public String getPassword() { return password; }
    public String getAuthProvider() { return authProvider != null ? authProvider : "LOCAL"; }
    public String getExternalSubject() { return externalSubject; }
    public String getExternalEmail() { return externalEmail; }
    public Boolean getExternalEmailVerified() { return externalEmailVerified; }

    public void setRoles(Set<Role> roles) {
        this.roles = roles == null ? new HashSet<>() : new HashSet<>(roles);
    }

    public void setPermissions(Set<String> permissions) {
        this.permissions = permissions == null ? new HashSet<>() : new HashSet<>(permissions);
    }
    
    @Override 
    public Set<String> getRoles() { 
        return roles.stream()
                .map(role -> role.getName().name())
                .collect(Collectors.toSet()); 
    }
    
    @Override public Set<String> getPermissions() { return permissions; }

    @PrePersist
    @PreUpdate
    void ensureIdentityDefaults() {
        if (authProvider == null || authProvider.isBlank()) {
            authProvider = "LOCAL";
        }
        if (externalEmailVerified == null) {
            externalEmailVerified = false;
        }
    }
}
