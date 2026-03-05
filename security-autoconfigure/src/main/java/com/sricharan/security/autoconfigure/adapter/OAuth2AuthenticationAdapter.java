package com.sricharan.security.autoconfigure.adapter;

import com.sricharan.security.autoconfigure.config.SecurityProperties;
import com.sricharan.security.core.adapter.AuthenticationAdapter;
import com.sricharan.security.core.user.AuthenticatedUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Converts Spring's {@link JwtAuthenticationToken} (from the OAuth2 Resource Server)
 * into a universal {@link AuthenticatedUser}.
 *
 * <p>Claim names are fully configurable via {@code security.oauth2.*} properties.
 * Defaults follow standard OIDC conventions:
 * <pre>
 *   preferred_username → username
 *   sub                → userId
 *   roles              → roles
 *   permissions        → permissions
 * </pre>
 *
 * <p>Active only when {@code security.auth-mode=OAUTH2}.
 */
public class OAuth2AuthenticationAdapter implements AuthenticationAdapter {

    protected final SecurityProperties.OAuth2Claims claims;

    public OAuth2AuthenticationAdapter(SecurityProperties properties) {
        this.claims = properties.getOauth2();
    }

    @Override
    public boolean supports(Authentication authentication) {
        return authentication instanceof JwtAuthenticationToken;
    }

    @Override
    public AuthenticatedUser convert(Authentication authentication) {
        JwtAuthenticationToken token = (JwtAuthenticationToken) authentication;
        Map<String, Object> attributes = token.getTokenAttributes();

        String username = getStringClaim(attributes, claims.getUsernameClaim());
        if (username == null) {
            username = getStringClaim(attributes, "sub"); // fallback to sub
        }

        String userId = getStringClaim(attributes, claims.getUserIdClaim());
        Set<String> roles = getListClaim(attributes, claims.getRolesClaim());
        Set<String> permissions = getListClaim(attributes, claims.getPermissionsClaim());

        return AuthenticatedUser.builder(username)
                .userId(userId)
                .roles(roles)
                .permissions(permissions)
                .build();
    }

    @Override
    public int getOrder() {
        return 10;
    }

    protected String getStringClaim(Map<String, Object> attributes, String claimName) {
        Object value = attributes.get(claimName);
        return value != null ? value.toString() : null;
    }

    @SuppressWarnings("unchecked")
    protected Set<String> getListClaim(Map<String, Object> attributes, String claimName) {
        Object value = attributes.get(claimName);
        if (value instanceof List<?> list) {
            Set<String> result = new HashSet<>();
            for (Object item : list) {
                if (item != null) result.add(item.toString());
            }
            return result;
        }
        return Collections.emptySet();
    }
}
