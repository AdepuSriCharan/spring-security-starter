package com.sricharan.security.autoconfigure.observability;

import com.sricharan.security.core.audit.SecurityAuditEventType;

/**
 * Metrics abstraction for security events.
 */
public interface SecurityMetricsRecorder {

    void increment(SecurityAuditEventType type, String outcome);

    void recordRefreshLatencyNanos(long nanos, String outcome);
}
