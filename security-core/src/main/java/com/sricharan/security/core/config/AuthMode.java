package com.sricharan.security.core.config;

/**
 * Selects the authentication mechanism used by the security starter.
 *
 * <p>Set via {@code security.auth-mode} in {@code application.properties}.
 *
 * <pre>
 * INTERNAL  — built-in JWT (default). /login, /refresh, /logout endpoints active.
 * OAUTH2    — delegates to Spring's OAuth2 Resource Server. Expects a Bearer JWT
 *             issued by an external IdP (standard OIDC claims).
 * KEYCLOAK  — like OAUTH2 but with automatic parsing of Keycloak's nested
 *             realm_access.roles / resource_access claims.
 * </pre>
 */
public enum AuthMode {

    /**
     * Default mode. The starter manages its own JWT issuance and verification.
     * Requires {@code security.jwt.secret}.
     */
    INTERNAL,

    /**
     * OAuth2 Resource Server mode. Spring validates the Bearer token against
     * an external IdP (e.g. Auth0, Google, Azure AD). Standard claims are used:
     * {@code sub}, {@code preferred_username}, {@code roles}, {@code permissions}.
     * Claim names are configurable via {@code security.oauth2.*} properties.
     */
    OAUTH2,

    /**
     * Keycloak-specific mode. Extends OAuth2 mode with automatic extraction of
     * Keycloak's nested claim structures:
     * {@code realm_access.roles} and {@code resource_access.<client>.roles}.
     * Configurable via {@code security.keycloak.*} properties.
     */
    KEYCLOAK
}
