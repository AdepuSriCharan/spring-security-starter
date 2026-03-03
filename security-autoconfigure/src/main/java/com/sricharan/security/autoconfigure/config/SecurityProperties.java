package com.sricharan.security.autoconfigure.config;

import com.sricharan.security.core.config.AuthMode;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration properties for the Spring Security Explainer starter.
 *
 * <p>All properties share the {@code security.*} prefix:
 * <ul>
 *   <li>{@code security.auth-mode} — authentication mode (INTERNAL / OAUTH2 / KEYCLOAK)</li>
 *   <li>{@code security.public-endpoints} — ant-matchers that bypass authentication</li>
 *   <li>{@code security.oauth2.*} — JWT claim names for OAUTH2 mode</li>
 *   <li>{@code security.keycloak.*} — JWT claim names for KEYCLOAK mode</li>
 * </ul>
 */
@ConfigurationProperties(prefix = "security")
public class SecurityProperties {

    /**
     * Authentication mode. Controls which authentication mechanism is active.
     * <ul>
     *   <li>{@code INTERNAL} (default) — built-in JWT, /login /refresh /logout endpoints</li>
     *   <li>{@code OAUTH2} — Spring OAuth2 Resource Server with configurable claim mapping</li>
     *   <li>{@code KEYCLOAK} — OAuth2 with automatic Keycloak realm_access/resource_access parsing</li>
     * </ul>
     */
    private AuthMode authMode = AuthMode.INTERNAL;

    /**
     * A list of endpoint ant-matchers that should be publicly accessible
     * without requiring authentication.
     * Examples: /register, /public/**, /docs
     */
    private List<String> publicEndpoints = new ArrayList<>();

    /**
     * JWT claim name mappings for {@code OAUTH2} mode.
     * See {@link OAuth2Claims} for defaults.
     */
    private final OAuth2Claims oauth2 = new OAuth2Claims();

    /**
     * JWT claim name mappings for {@code KEYCLOAK} mode.
     * See {@link KeycloakClaims} for defaults.
     */
    private final KeycloakClaims keycloak = new KeycloakClaims();

    public AuthMode getAuthMode() {
        return authMode;
    }

    public void setAuthMode(AuthMode authMode) {
        this.authMode = authMode;
    }

    public List<String> getPublicEndpoints() {
        return publicEndpoints;
    }

    public void setPublicEndpoints(List<String> publicEndpoints) {
        this.publicEndpoints = publicEndpoints;
    }

    public OAuth2Claims getOauth2() {
        return oauth2;
    }

    public KeycloakClaims getKeycloak() {
        return keycloak;
    }


    /**
     * JWT claim name mappings used when {@code security.auth-mode=OAUTH2}.
     *
     * <pre>
     * security:
     *   oauth2:
     *     username-claim: preferred_username
     *     user-id-claim: sub
     *     roles-claim: roles
     *     permissions-claim: permissions
     * </pre>
     */
    public static class OAuth2Claims {

        /** JWT claim that holds the username. Default: {@code preferred_username} */
        private String usernameClaim = "preferred_username";

        /** JWT claim that holds the user ID. Default: {@code sub} */
        private String userIdClaim = "sub";

        /** JWT claim that holds the list of roles. Default: {@code roles} */
        private String rolesClaim = "roles";

        /** JWT claim that holds the list of permissions. Default: {@code permissions} */
        private String permissionsClaim = "permissions";

        public String getUsernameClaim() { return usernameClaim; }
        public void setUsernameClaim(String usernameClaim) { this.usernameClaim = usernameClaim; }

        public String getUserIdClaim() { return userIdClaim; }
        public void setUserIdClaim(String userIdClaim) { this.userIdClaim = userIdClaim; }

        public String getRolesClaim() { return rolesClaim; }
        public void setRolesClaim(String rolesClaim) { this.rolesClaim = rolesClaim; }

        public String getPermissionsClaim() { return permissionsClaim; }
        public void setPermissionsClaim(String permissionsClaim) { this.permissionsClaim = permissionsClaim; }
    }


    /**
     * JWT claim name mappings used when {@code security.auth-mode=KEYCLOAK}.
     *
     * <pre>
     * security:
     *   keycloak:
     *     realm-access-claim: realm_access
     *     client-id: my-app
     *     resource-access-claim: resource_access
     *     roles-key: roles
     * </pre>
     */
    public static class KeycloakClaims {

        /**
         * The nested claim path for realm-level roles.
         * Default: {@code realm_access} (Keycloak standard — roles live at
         * {@code realm_access.roles}).
         */
        private String realmAccessClaim = "realm_access";

        /**
         * Your Keycloak client ID for extracting client-level roles from
         * {@code resource_access.<clientId>.roles}.
         * Leave blank to skip client-role extraction.
         */
        private String clientId = "";

        /**
         * The nested claim path for client-level roles.
         * Default: {@code resource_access}
         */
        private String resourceAccessClaim = "resource_access";

        /**
         * The key inside {@code realm_access} and {@code resource_access.<client>}
         * that holds the list of role strings.
         * Default: {@code roles} (Keycloak standard).
         * Change this only if your Keycloak setup renames the inner roles array.
         */
        private String rolesKey = "roles";

        public String getRealmAccessClaim() { return realmAccessClaim; }
        public void setRealmAccessClaim(String realmAccessClaim) { this.realmAccessClaim = realmAccessClaim; }

        public String getClientId() { return clientId; }
        public void setClientId(String clientId) { this.clientId = clientId; }

        public String getResourceAccessClaim() { return resourceAccessClaim; }
        public void setResourceAccessClaim(String resourceAccessClaim) { this.resourceAccessClaim = resourceAccessClaim; }

        public String getRolesKey() { return rolesKey; }
        public void setRolesKey(String rolesKey) { this.rolesKey = rolesKey; }
    }
}
