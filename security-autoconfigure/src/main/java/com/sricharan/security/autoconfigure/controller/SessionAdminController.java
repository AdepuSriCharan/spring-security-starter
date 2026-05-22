package com.sricharan.security.autoconfigure.controller;

import com.sricharan.security.autoconfigure.observability.SecurityEventRecorder;
import com.sricharan.security.core.annotation.RequireRole;
import com.sricharan.security.core.audit.SecurityAuditEventType;
import com.sricharan.security.core.token.RefreshSession;
import com.sricharan.security.core.token.RefreshTokenStore;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Admin endpoints for refresh-token-backed session management.
 */
@RestController
@RequestMapping("/security/sessions")
public class SessionAdminController {

    private final RefreshTokenStore refreshTokenStore;
    private final SecurityEventRecorder securityEventRecorder;

    public SessionAdminController(
            RefreshTokenStore refreshTokenStore,
            SecurityEventRecorder securityEventRecorder) {
        this.refreshTokenStore = refreshTokenStore;
        this.securityEventRecorder = securityEventRecorder;
    }

    @GetMapping
    @RequireRole("ADMIN")
    public List<RefreshSession> listSessions(@RequestParam String userId) {
        return refreshTokenStore.listActiveSessions(userId);
    }

    @DeleteMapping("/{sessionId}")
    @RequireRole("ADMIN")
    public ResponseEntity<Map<String, Object>> revokeSession(
            @PathVariable String sessionId,
            @RequestParam String userId) {
        boolean revoked = refreshTokenStore.revokeSession(userId, sessionId);
        if (!revoked) {
            return errorResponse(HttpStatus.NOT_FOUND, "Session not found for user.");
        }

        securityEventRecorder.record(
                SecurityAuditEventType.SESSION_REVOKED,
                "SUCCESS",
                userId,
                null,
                Map.of("scope", "single_session", "sessionId", sessionId));
        return successResponse("Session revoked.");
    }

    @DeleteMapping("/user/{userId}")
    @RequireRole("ADMIN")
    public ResponseEntity<Map<String, Object>> revokeAllSessions(@PathVariable String userId) {
        refreshTokenStore.revokeAllForUser(userId);
        securityEventRecorder.record(
                SecurityAuditEventType.SESSION_REVOKED,
                "SUCCESS",
                userId,
                null,
                Map.of("scope", "all_sessions"));
        return successResponse("All sessions revoked.");
    }

    private ResponseEntity<Map<String, Object>> successResponse(String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("message", message);
        body.put("timestamp", Instant.now().toString());
        return ResponseEntity.ok(body);
    }

    private ResponseEntity<Map<String, Object>> errorResponse(HttpStatus status, String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", status.name());
        body.put("message", message);
        body.put("timestamp", Instant.now().toString());
        return ResponseEntity.status(status).body(body);
    }
}
