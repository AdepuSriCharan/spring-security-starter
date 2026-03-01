package com.sricharan.security.core.account;

import java.util.Set;

/**
 * Represents the essential user details required for authentication
 * and token generation.
 *
 * <p>This interface abstracts away the underlying storage mechanism (e.g., JPA Entity,
 * Mongo Document, or external API response) from the security framework.
 */
public interface UserAccount {

    /**
     * @return The unique identifier of the user (e.g., UUID string, database ID).
     */
    String getId();

    /**
     * @return The username used for login.
     */
    String getUsername();

    /**
     * @return The hashed password for verification.
     */
    String getPassword();

    /**
     * @return The set of roles assigned to the user.
     */
    Set<String> getRoles();

    /**
     * @return The set of explicit permissions assigned to the user.
     */
    Set<String> getPermissions();
}
