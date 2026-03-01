package com.sricharan.security.core.authorization;

import com.sricharan.security.core.exception.SecurityAuthorizationException;
import com.sricharan.security.core.exception.SecurityAuthorizationException.AuthorizationType;
import com.sricharan.security.core.user.AuthenticatedUser;

import java.util.Arrays;
import java.util.Set;

/**
 * Default authorization logic: simple set-intersection.
 *
 * <ul>
 *   <li>Role check: user's roles ∩ required roles ≠ ∅ → allow</li>
 *   <li>Permission check: user's permissions ∩ required permissions ≠ ∅ → allow</li>
 * </ul>
 *
 * <p>Replace this bean to implement hierarchical RBAC, ABAC, or
 * policy-engine-backed authorization.
 */
public class DefaultAuthorizationManager implements AuthorizationManager {

    @Override
    public void checkRole(AuthenticatedUser user, String[] roles) {
        Set<String> userRoles = user.getRoles();
        boolean hasRole = Arrays.stream(roles).anyMatch(userRoles::contains);

        if (!hasRole) {
            throw new SecurityAuthorizationException(
                    user.getUsername(),
                    roles,
                    userRoles,
                    AuthorizationType.ROLE);
        }
    }

    @Override
    public void checkPermission(AuthenticatedUser user, String[] permissions) {
        Set<String> userPermissions = user.getPermissions();
        boolean hasPermission = Arrays.stream(permissions).anyMatch(userPermissions::contains);

        if (!hasPermission) {
            throw new SecurityAuthorizationException(
                    user.getUsername(),
                    permissions,
                    userPermissions,
                    AuthorizationType.PERMISSION);
        }
    }
}
