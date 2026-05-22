package com.sricharan.security.autoconfigure.controller;

import com.sricharan.security.autoconfigure.observability.SecurityEventRecorder;
import com.sricharan.security.core.audit.SecurityAuditEventType;
import com.sricharan.security.core.token.RefreshSession;
import com.sricharan.security.core.token.RefreshTokenStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SessionAdminControllerTest {

    private RefreshTokenStore refreshTokenStore;
    private SecurityEventRecorder securityEventRecorder;
    private SessionAdminController controller;

    @BeforeEach
    void setUp() {
        refreshTokenStore = mock(RefreshTokenStore.class);
        securityEventRecorder = mock(SecurityEventRecorder.class);
        controller = new SessionAdminController(refreshTokenStore, securityEventRecorder);
    }

    @Test
    void listSessionsReturnsStoreSessions() {
        List<RefreshSession> sessions = List.of(
                new RefreshSession("s1", "user-1", Instant.now().plusSeconds(60))
        );
        when(refreshTokenStore.listActiveSessions("user-1")).thenReturn(sessions);

        List<RefreshSession> response = controller.listSessions("user-1");

        assertThat(response).containsExactlyElementsOf(sessions);
    }

    @Test
    void revokeSessionReturnsNotFoundWhenMissing() {
        when(refreshTokenStore.revokeSession("user-1", "s1")).thenReturn(false);

        var response = controller.revokeSession("s1", "user-1");

        assertThat(response.getStatusCode().value()).isEqualTo(404);
        assertThat(response.getBody()).containsEntry("error", "NOT_FOUND");
    }

    @Test
    void revokeSessionReturnsOkAndEmitsAuditEvent() {
        when(refreshTokenStore.revokeSession("user-1", "s1")).thenReturn(true);

        var response = controller.revokeSession("s1", "user-1");

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).containsEntry("message", "Session revoked.");

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, String>> detailsCaptor = ArgumentCaptor.forClass(Map.class);
        verify(securityEventRecorder).record(
                eq(SecurityAuditEventType.SESSION_REVOKED),
                eq("SUCCESS"),
                eq("user-1"),
                eq(null),
                detailsCaptor.capture()
        );
        assertThat(detailsCaptor.getValue())
                .containsEntry("scope", "single_session")
                .containsEntry("sessionId", "s1");
    }

    @Test
    void revokeAllSessionsReturnsOkAndEmitsAuditEvent() {
        var response = controller.revokeAllSessions("user-1");

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).containsEntry("message", "All sessions revoked.");
        verify(refreshTokenStore).revokeAllForUser("user-1");
        verify(securityEventRecorder).record(
                SecurityAuditEventType.SESSION_REVOKED,
                "SUCCESS",
                "user-1",
                null,
                Map.of("scope", "all_sessions")
        );
    }
}
