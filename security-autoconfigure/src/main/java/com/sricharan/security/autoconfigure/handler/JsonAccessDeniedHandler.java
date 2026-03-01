package com.sricharan.security.autoconfigure.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;
import java.time.Instant;

/**
 * Returns a structured JSON response when an authenticated user lacks
 * sufficient permissions for a resource (HTTP 403).
 *
 * <p>This replaces Spring Security's default HTML-based denied handler,
 * ensuring REST APIs always receive machine-readable error responses.
 *
 * <p>Example response:
 * <pre>
 * {
 *   "error": "FORBIDDEN",
 *   "message": "You do not have permission to access this resource",
 *   "timestamp": "2026-03-01T14:00:00Z"
 * }
 * </pre>
 */
public class JsonAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        String json = """
                {
                  "error": "FORBIDDEN",
                  "message": "You do not have permission to access this resource",
                  "timestamp": "%s"
                }
                """.formatted(Instant.now().toString());

        response.getWriter().write(json);
    }
}
