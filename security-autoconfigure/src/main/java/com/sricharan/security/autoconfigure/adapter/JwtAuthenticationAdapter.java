package com.sricharan.security.autoconfigure.adapter;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.sricharan.security.autoconfigure.jwt.JwtAuthenticationToken;
import com.sricharan.security.core.adapter.AuthenticationAdapter;
import com.sricharan.security.core.user.AuthenticatedUser;
import org.springframework.security.core.Authentication;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Converts a verified {@link JwtAuthenticationToken} into a universal
 * {@link AuthenticatedUser} by reading claims from the JWT payload.
 */
public class JwtAuthenticationAdapter implements AuthenticationAdapter {

    @Override
    public boolean supports(Authentication authentication) {
        return authentication instanceof JwtAuthenticationToken;
    }

    @Override
    public AuthenticatedUser convert(Authentication authentication) {
        JwtAuthenticationToken jwtToken = (JwtAuthenticationToken) authentication;
        DecodedJWT jwt = jwtToken.getDecodedJWT();

        String username = jwt.getSubject();
        String userId = jwt.getClaim("userId").asString();

        List<String> rolesList = jwt.getClaim("roles").asList(String.class);
        Set<String> roles = rolesList != null ? new HashSet<>(rolesList) : new HashSet<>();

        List<String> permissionsList = jwt.getClaim("permissions").asList(String.class);
        Set<String> permissions = permissionsList != null ? new HashSet<>(permissionsList) : new HashSet<>();

        return AuthenticatedUser.builder(username)
                .userId(userId)
                .roles(roles)
                .permissions(permissions)
                .build();
    }
}
