package com.sricharan.security.core.adapter;

import com.sricharan.security.core.user.AuthenticatedUser;
import org.springframework.security.core.Authentication;

/**
 * Pluggable bridge between any authentication mechanism and
 * the library's {@link AuthenticatedUser}.
 *
 * <p>Implementations convert a Spring Security {@link Authentication}
 * into an {@link AuthenticatedUser}. This is the key abstraction that
 * makes the library independent of the login mechanism.
 *
 * <h3>Built-in adapters (provided in autoconfigure):</h3>
 * <ul>
 *   <li>{@code JwtAuthenticationAdapter} — for internal JWT tokens</li>
 *   <li>{@code OAuth2AuthenticationAdapter} — for external OAuth2/OIDC providers</li>
 *   <li>{@code KeycloakAuthenticationAdapter} — for Keycloak nested claim structure</li>
 *   <li>{@code SpringSecurityAuthenticationAdapter} — fallback for {@code UsernamePasswordAuthenticationToken}</li>
 * </ul>
 *
 * <p>Register a custom adapter as a Spring bean and it will be picked up
 * automatically by the {@code SecurityContextFilter}.
 */
public interface AuthenticationAdapter {

    /**
     * Does this adapter support the given authentication type?
     *
     * @param authentication the Spring Security authentication object
     * @return {@code true} if this adapter can convert it
     */
    boolean supports(Authentication authentication);

    /**
     * Convert the authentication to an {@link AuthenticatedUser}.
     *
     * @param authentication the Spring Security authentication object
     * @return the universal user representation
     */
    AuthenticatedUser convert(Authentication authentication);

    /**
     * Adapter priority. Lower values = higher priority.
     * Default is 100. Override to control adapter selection order.
     */
    default int getOrder() {
        return 100;
    }
}
