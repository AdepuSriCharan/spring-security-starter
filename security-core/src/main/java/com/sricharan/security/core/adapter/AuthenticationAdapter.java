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
 *   <li>{@code SpringSecurityAuthenticationAdapter} — for {@code UsernamePasswordAuthenticationToken}</li>
 * </ul>
 *
 * <h3>Future adapters (Phase 4–5):</h3>
 * <ul>
 *   <li>JWT token adapter</li>
 *   <li>Keycloak token adapter</li>
 *   <li>OAuth2 token adapter</li>
 * </ul>
 *
 * <p>Register your adapter as a Spring bean and it will be picked up
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
