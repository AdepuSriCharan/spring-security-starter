package com.sricharan.security.autoconfigure.filter;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.sricharan.security.autoconfigure.jwt.JwtAuthenticationToken;
import com.sricharan.security.autoconfigure.jwt.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Intercepts incoming requests to extract and validate Bearer JWTs.
 *
 * <p>If a valid JWT is found in the {@code Authorization} header, a
 * {@link JwtAuthenticationToken} is placed into the Spring
 * {@link SecurityContextHolder}. The subsequent {@link SecurityContextFilter}
 * will bridge it to an {@link com.sricharan.security.core.user.AuthenticatedUser}.
 *
 * <p>If the token is invalid or expired, the security context is explicitly
 * cleared to prevent stale authentication from leaking across pooled threads.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;

    public JwtAuthenticationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        String header = request.getHeader(AUTHORIZATION_HEADER);

        if (StringUtils.hasText(header) && header.startsWith(BEARER_PREFIX)) {
            String token = header.substring(BEARER_PREFIX.length());
            try {
                DecodedJWT decodedJWT = jwtService.verifyToken(token);
                JwtAuthenticationToken authentication = new JwtAuthenticationToken(decodedJWT);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (JWTVerificationException e) {
                SecurityContextHolder.clearContext();
                logger.debug("JWT verification failed: " + e.getMessage());
            }
        }

        filterChain.doFilter(request, response);
    }
}
