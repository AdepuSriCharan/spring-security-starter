package com.sricharan.security.autoconfigure.filter;

import com.sricharan.security.core.adapter.AuthenticationAdapter;
import com.sricharan.security.core.context.SecurityUserContext;
import com.sricharan.security.core.user.AuthenticatedUser;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Comparator;
import java.util.List;

/**
 * Bridges Spring Security's {@link Authentication} with the library's
 * {@link AuthenticatedUser} via registered {@link AuthenticationAdapter}s.
 *
 * <ol>
 *   <li>Reads the authentication from {@code SecurityContextHolder}</li>
 *   <li>Finds a matching adapter (sorted by priority)</li>
 *   <li>Converts to {@link AuthenticatedUser}</li>
 *   <li>Stores in {@link SecurityUserContext}</li>
 *   <li>Clears the context in {@code finally} to prevent ThreadLocal leaks</li>
 * </ol>
 */
public class SecurityContextFilter extends OncePerRequestFilter {

    private final List<AuthenticationAdapter> adapters;

    public SecurityContextFilter(List<AuthenticationAdapter> adapters) {
        this.adapters = adapters.stream()
                .sorted(Comparator.comparingInt(AuthenticationAdapter::getOrder))
                .toList();
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication != null && authentication.isAuthenticated()) {
                AuthenticatedUser user = adaptAuthentication(authentication);
                if (user != null) {
                    SecurityUserContext.setCurrentUser(user);
                }
            }

            filterChain.doFilter(request, response);
        } finally {
            SecurityUserContext.clear();
        }
    }

    private AuthenticatedUser adaptAuthentication(Authentication authentication) {
        for (AuthenticationAdapter adapter : adapters) {
            if (adapter.supports(authentication)) {
                return adapter.convert(authentication);
            }
        }
        return null;
    }
}
