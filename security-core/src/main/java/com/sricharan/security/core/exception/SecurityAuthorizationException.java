package com.sricharan.security.core.exception;

import java.util.Arrays;
import java.util.Set;

/**
 * Thrown when an authenticated user does not have the required
 * roles or permissions to access a resource.
 *
 * <p>This is the library's own exception — not Spring Security's
 * {@code AccessDeniedException}. This gives developers clean,
 * framework-independent error information.
 */
public class SecurityAuthorizationException extends RuntimeException {

    private final String username;
    private final String[] required;
    private final Set<String> actual;
    private final AuthorizationType type;
    private final String resourceId;

    public SecurityAuthorizationException(
            String username,
            String[] required,
            Set<String> actual,
            AuthorizationType type) {
        this(username, required, actual, type, null);
    }

    public SecurityAuthorizationException(
            String username,
            String[] required,
            Set<String> actual,
            AuthorizationType type,
            String resourceId) {
        super(buildMessage(username, required, actual, type, resourceId));
        this.username = username;
        this.required = required;
        this.actual = actual;
        this.type = type;
        this.resourceId = resourceId;
    }

    public String getUsername() {
        return username;
    }

    public String[] getRequired() {
        return required;
    }

    public Set<String> getActual() {
        return actual;
    }

    public AuthorizationType getType() {
        return type;
    }

    public String getResourceId() {
        return resourceId;
    }

    private static String buildMessage(
            String username,
            String[] required,
            Set<String> actual,
            AuthorizationType type,
            String resourceId) {

        if (type == AuthorizationType.OWNERSHIP) {
            return String.format(
                    "Access denied for user '%s'. Not the owner of resource '%s'.",
                    username,
                    resourceId
            );
        }

        return String.format(
                "Access denied for user '%s'. Required %s: %s. User has: %s",
                username,
                type.name().toLowerCase(),
                Arrays.toString(required),
                actual);
    }

    /**
     * Distinguishes between role-based and permission-based denials.
     */
    public enum AuthorizationType {
        ROLE,
        PERMISSION,
        OWNERSHIP
    }
}
