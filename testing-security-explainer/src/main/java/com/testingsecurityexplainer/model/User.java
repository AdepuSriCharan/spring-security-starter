package com.testingsecurityexplainer.model;

import com.sricharan.security.core.account.UserAccount;
import jakarta.persistence.*;
import java.util.Set;

/**
 * JPA entity that represents a user stored in the database.
 * Implements UserAccount so it can be used directly with the security framework.
 */
@Entity
@Table(name = "users")
public class User implements UserAccount {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "role")
    private Set<String> roles;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_permissions", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "permission")
    private Set<String> permissions;

    // Required by JPA
    protected User() {}

    public User(String username, String password, Set<String> roles, Set<String> permissions) {
        this.username = username;
        this.password = password;
        this.roles = roles;
        this.permissions = permissions;
    }

    @Override public String getId() { return id; }
    @Override public String getUsername() { return username; }
    @Override public String getPassword() { return password; }
    @Override public Set<String> getRoles() { return roles; }
    @Override public Set<String> getPermissions() { return permissions; }
}
