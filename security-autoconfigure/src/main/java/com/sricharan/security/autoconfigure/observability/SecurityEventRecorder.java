package com.sricharan.security.autoconfigure.observability;

import com.sricharan.security.core.audit.SecurityAuditEvent;
import com.sricharan.security.core.audit.SecurityAuditEventType;
import com.sricharan.security.core.audit.SecurityAuditSink;
import org.slf4j.MDC;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Central recorder that emits security audit logs and metrics.
 */
public class SecurityEventRecorder {

    private final SecurityAuditSink auditSink;
    private final SecurityMetricsRecorder metricsRecorder;

    public SecurityEventRecorder(SecurityAuditSink auditSink, SecurityMetricsRecorder metricsRecorder) {
        this.auditSink = auditSink;
        this.metricsRecorder = metricsRecorder;
    }

    public void record(SecurityAuditEventType type, String outcome, String userId, String username, Map<String, String> details) {
        Map<String, String> merged = new LinkedHashMap<>();
        if (details != null) {
            merged.putAll(details);
        }

        String traceId = MDC.get("traceId");
        String requestId = MDC.get("requestId");
        if (traceId != null && !traceId.isBlank()) {
            merged.put("traceId", traceId);
        }
        if (requestId != null && !requestId.isBlank()) {
            merged.put("requestId", requestId);
        }

        SecurityAuditEvent event = new SecurityAuditEvent(
                Instant.now(),
                type,
                outcome,
                userId,
                username,
                merged);

        auditSink.publish(event);
        metricsRecorder.increment(type, outcome);
    }

    public void recordRefreshLatencyNanos(long nanos, String outcome) {
        metricsRecorder.recordRefreshLatencyNanos(nanos, outcome);
    }
}
