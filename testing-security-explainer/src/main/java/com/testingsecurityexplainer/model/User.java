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
        this.roles = roles;
        this.permissions = permissions;
    }

    @Override public String getId() { return id; }
    @Override public String getUsername() { return username; }
    @Override public String getPassword() { return password; }
    
    @Override 
    public Set<String> getRoles() { 
        return roles.stream()
                .map(role -> role.getName().name())
                .collect(Collectors.toSet()); 
    }
    
    @Override public Set<String> getPermissions() { return permissions; }
}
