package com.sricharan.security.autoconfigure.handler;

import com.sricharan.security.autoconfigure.observability.SecurityEventRecorder;
import com.sricharan.security.core.audit.SecurityAuditEventType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

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

    private final SecurityEventRecorder securityEventRecorder;

    public JsonAuthenticationEntryPoint(SecurityEventRecorder securityEventRecorder) {
        this.securityEventRecorder = securityEventRecorder;
    }

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {

        Map<String, String> details = new LinkedHashMap<>();
        details.put("path", request.getRequestURI());
        details.put("method", request.getMethod());
        securityEventRecorder.record(SecurityAuditEventType.UNAUTHORIZED, "FAILURE", null, null, details);

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
