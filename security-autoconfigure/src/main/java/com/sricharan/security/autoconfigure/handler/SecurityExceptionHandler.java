package com.sricharan.security.autoconfigure.handler;

import com.sricharan.security.core.exception.SecurityAuthorizationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Global exception handler that catches {@link SecurityAuthorizationException}
 * and returns a clean, readable JSON response.
 *
 * <p>Example response:
 * <pre>
 * {
 *   "error": "FORBIDDEN",
 *   "message": "Access denied for user 'john'. Required role: [ADMIN]. User has: [USER]",
 *   "type": "ROLE",
 *   "required": ["ADMIN"],
 *   "actual": ["USER"],
 *   "timestamp": "2026-02-28T14:00:00Z"
 * }
 * </pre>
 */
@RestControllerAdvice
public class SecurityExceptionHandler {

    @ExceptionHandler(SecurityAuthorizationException.class)
    public ResponseEntity<Map<String, Object>> handleAuthorizationException(
            SecurityAuthorizationException ex) {

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "FORBIDDEN");
        body.put("message", ex.getMessage());
        body.put("type", ex.getType().name());

        if (ex.getType() == SecurityAuthorizationException.AuthorizationType.OWNERSHIP) {
            body.put("resourceId", ex.getResourceId());
        } else {
            body.put("required", ex.getRequired());
            body.put("actual", ex.getActual());
        }

        body.put("timestamp", Instant.now().toString());

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(body);
    }

    /**
     * Catch IllegalStateException from SecurityUserContext.requireCurrentUser()
     * when no user is authenticated.
     */
    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<Map<String, Object>> handleNoUserException(
            IllegalStateException ex) {

        if (ex.getMessage() != null && ex.getMessage().contains("SecurityUserContext")) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("error", "UNAUTHORIZED");
            body.put("message", "Authentication required to access this resource");
            body.put("timestamp", Instant.now().toString());

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
        }

        // Re-throw if it's not our exception
        throw ex;
    }
}
