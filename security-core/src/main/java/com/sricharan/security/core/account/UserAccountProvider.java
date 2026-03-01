package com.sricharan.security.core.account;

import java.util.Optional;

/**
 * Service Provider Interface (SPI) for retrieving {@link UserAccount} data.
 *
 * <p>To enable the built-in login functionality, developers must provide a
 * Spring Bean implementing this interface. The framework will use this provision
 * to lookup users during the authentication process, keeping the framework completely
 * independent of the data access layer (e.g. Spring Data JPA).
 */
public interface UserAccountProvider {

    /**
     * Finds a user account by their username.
     *
     * @param username The username provided during login.
     * @return An Optional containing the UserAccount if found, otherwise empty.
     */
    Optional<UserAccount> findByUsername(String username);
}
