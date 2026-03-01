package com.sricharan.security.core.authorization;

import com.sricharan.security.core.user.AuthenticatedUser;

/**
 * Core authorization contract.
 *
 * <p>Implementations decide whether an {@link AuthenticatedUser} is allowed
 * to proceed based on required roles or permissions.
 *
 * <p>The default implementation ({@code DefaultAuthorizationManager}) uses
 * simple set-intersection logic. Developers can replace it with a custom
 * bean if they need RBAC hierarchies, ABAC, or external policy engines.
 */
public interface AuthorizationManager {

    /**
     * Check that the user holds at least one of the required roles.
     *
     * @param user  the authenticated user
     * @param roles the required roles (OR logic)
     * @throws com.sricharan.security.core.exception.SecurityAuthorizationException
     *         if the user lacks the required roles
     */
    void checkRole(AuthenticatedUser user, String[] roles);

    /**
     * Check that the user holds at least one of the required permissions.
     *
     * @param user        the authenticated user
     * @param permissions the required permissions (OR logic)
     * @throws com.sricharan.security.core.exception.SecurityAuthorizationException
     *         if the user lacks the required permissions
     */
    void checkPermission(AuthenticatedUser user, String[] permissions);
}
