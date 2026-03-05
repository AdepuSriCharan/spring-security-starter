package com.sricharan.security.autoconfigure.adapter;

import com.sricharan.security.autoconfigure.config.SecurityProperties;
import com.sricharan.security.core.user.AuthenticatedUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Extends {@link OAuth2AuthenticationAdapter} to handle Keycloak's nested
 * claim structure for role extraction.
 *
 * <p>Keycloak issues roles in two nested structures:
 * <pre>
 * "realm_access": {
 *     "roles": ["ADMIN", "USER"]
 * },
 * "resource_access": {
 *     "my-client": {
 *         "roles": ["client-role"]
 *     }
 * }
 * </pre>
 *
 * <p>Realm-level roles go to {@link AuthenticatedUser#getRoles()}, while
 * client-level roles are treated as fine-grained permissions and go to
 * {@link AuthenticatedUser#getPermissions()}.
 * Configurable via:
 * <pre>
 * security.keycloak.realm-access-claim=realm_access   # default
 * security.keycloak.client-id=my-client               # optional, for resource_access
 * security.keycloak.resource-access-claim=resource_access # default
 * </pre>
 *
 * <p>Active only when {@code security.auth-mode=KEYCLOAK}.
 */
public class KeycloakAuthenticationAdapter extends OAuth2AuthenticationAdapter {

    private final SecurityProperties.KeycloakClaims keycloakClaims;

    public KeycloakAuthenticationAdapter(SecurityProperties properties) {
        super(properties);
        this.keycloakClaims = properties.getKeycloak();
    }

    @Override
    public boolean supports(Authentication authentication) {
        return authentication instanceof JwtAuthenticationToken;
    }

    @Override
    public AuthenticatedUser convert(Authentication authentication) {
        JwtAuthenticationToken token = (JwtAuthenticationToken) authentication;
        Map<String, Object> attributes = token.getTokenAttributes();

        // Use configurable claim names from parent's OAuth2Claims
        String username = getStringClaim(attributes, claims.getUsernameClaim());
        if (username == null) {
            username = getStringClaim(attributes, claims.getUserIdClaim()); // fallback
        }

        String userId = getStringClaim(attributes, claims.getUserIdClaim());

        // Extract realm-level roles from Keycloak's nested structure
        Set<String> roles = new HashSet<>(extractRealmRoles(attributes));

        // Client-level roles → treated as permissions (fine-grained access)
        Set<String> permissions = new HashSet<>();
        if (StringUtils.hasText(keycloakClaims.getClientId())) {
            permissions.addAll(extractClientRoles(attributes));
        }

        // Also merge any explicit permissions claim (if present)
        permissions.addAll(getListClaim(attributes, claims.getPermissionsClaim()));

        return AuthenticatedUser.builder(username)
                .userId(userId)
                .roles(roles)
                .permissions(permissions)
                .build();
    }

    @Override
    public int getOrder() {
        return 5; // highest priority — more specific than OAuth2 adapter
    }

    @SuppressWarnings("unchecked")
    private Set<String> extractRealmRoles(Map<String, Object> attributes) {
        Object realmAccess = attributes.get(keycloakClaims.getRealmAccessClaim());
        if (realmAccess instanceof Map<?, ?> realmMap) {
            Object roles = realmMap.get(keycloakClaims.getRolesKey());
            if (roles instanceof List<?> roleList) {
                Set<String> result = new HashSet<>();
                for (Object r : roleList) result.add(r.toString());
                return result;
            }
        }
        return Collections.emptySet();
    }

    @SuppressWarnings("unchecked")
    private Set<String> extractClientRoles(Map<String, Object> attributes) {
        Object resourceAccess = attributes.get(keycloakClaims.getResourceAccessClaim());
        if (resourceAccess instanceof Map<?, ?> resourceMap) {
            Object clientAccess = resourceMap.get(keycloakClaims.getClientId());
            if (clientAccess instanceof Map<?, ?> clientMap) {
                Object roles = clientMap.get(keycloakClaims.getRolesKey());
                if (roles instanceof List<?> roleList) {
                    Set<String> result = new HashSet<>();
                    for (Object r : roleList) result.add(r.toString());
                    return result;
                }
            }
        }
        return Collections.emptySet();
    }
}
