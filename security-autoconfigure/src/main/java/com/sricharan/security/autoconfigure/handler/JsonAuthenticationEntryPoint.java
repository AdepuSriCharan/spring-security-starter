package com.sricharan.security.autoconfigure.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.time.Instant;

/**
 * Returns a structured JSON response for unauthenticated requests (HTTP 401).
 *
 * <p>This replaces Spring Security's default HTML-based entry point,
 * ensuring REST APIs always receive machine-readable error responses.
 *
 * <p>Example response:
 * <pre>
 * {
 *   "error": "UNAUTHORIZED",
 *   "message": "Authentication required to access this resource",
 *   "timestamp": "2026-03-01T14:00:00Z"
 * }
 * </pre>
 */
public class JsonAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        String json = """
                {
                  "error": "UNAUTHORIZED",
                  "message": "Authentication required to access this resource",
                  "timestamp": "%s"
                }
                """.formatted(Instant.now().toString());

        response.getWriter().write(json);
    }
}
