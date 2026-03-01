package com.sricharan.security.autoconfigure.jwt;

import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.util.Collections;

/**
 * Bridges a verified {@link DecodedJWT} into Spring Security's
 * {@link org.springframework.security.core.Authentication} contract.
 *
 * <p>Populated by {@link com.sricharan.security.autoconfigure.filter.JwtAuthenticationFilter}
 * and converted to {@link com.sricharan.security.core.user.AuthenticatedUser} by
 * {@link com.sricharan.security.autoconfigure.adapter.JwtAuthenticationAdapter}.
 */
public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private final DecodedJWT decodedJWT;

    public JwtAuthenticationToken(DecodedJWT decodedJWT) {
        super(Collections.emptyList());
        this.decodedJWT = decodedJWT;
        super.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return decodedJWT.getToken();
    }

    @Override
    public Object getPrincipal() {
        return decodedJWT.getSubject();
    }

    public DecodedJWT getDecodedJWT() {
        return decodedJWT;
    }
}
