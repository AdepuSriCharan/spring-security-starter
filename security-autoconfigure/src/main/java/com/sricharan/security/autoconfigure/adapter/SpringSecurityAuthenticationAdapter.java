package com.sricharan.security.autoconfigure.adapter;

import com.sricharan.security.core.adapter.AuthenticationAdapter;
import com.sricharan.security.core.user.AuthenticatedUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Fallback adapter that converts Spring Security's standard
 * {@link org.springframework.security.authentication.UsernamePasswordAuthenticationToken}
 * (backed by {@link UserDetails}) into an {@link AuthenticatedUser}.
 *
 * <p>Roles are extracted from {@link GrantedAuthority} with the
 * {@code ROLE_} prefix stripped. Runs at low priority (order 1000)
 * so specific adapters like JWT or Keycloak take precedence.
 */
public class SpringSecurityAuthenticationAdapter implements AuthenticationAdapter {

    private static final String ROLE_PREFIX = "ROLE_";

    @Override
    public boolean supports(Authentication authentication) {
        return authentication != null
                && authentication.isAuthenticated()
                && authentication.getPrincipal() instanceof UserDetails;
    }

    @Override
    public AuthenticatedUser convert(Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        Set<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .map(this::stripRolePrefix)
                .collect(Collectors.toSet());

        return AuthenticatedUser.builder(userDetails.getUsername())
                .roles(roles)
                .permissions(Collections.emptySet())
                .build();
    }

    @Override
    public int getOrder() {
        return 1000;
    }

    private String stripRolePrefix(String authority) {
        if (authority.startsWith(ROLE_PREFIX)) {
            return authority.substring(ROLE_PREFIX.length());
        }
        return authority;
    }
}
