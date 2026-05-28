package com.sricharan.security.core.account;

import com.sricharan.security.core.identity.ExternalIdentityProfile;

import java.util.Optional;

/**
 * Optional SPI for apps that want to accept external identities
 * and map them onto local application users.
 *
 * <p>This is the bridge used by the Google sign-in flow:
 * verify the external identity, then either link to an existing user
 * or create a local account and return it.
 */
public interface ExternalIdentityAccountLinker {

    /**
     * Finds a local user that is already linked to the external identity.
     */
    Optional<UserAccount> findByExternalIdentity(String provider, String subject);

    /**
     * Finds a local user by email, if the app wants to auto-link by email.
     */
    Optional<UserAccount> findByEmail(String email);

    /**
     * Creates or links a local user for the external identity profile.
     */
    UserAccount createOrLink(ExternalIdentityProfile profile);
}
