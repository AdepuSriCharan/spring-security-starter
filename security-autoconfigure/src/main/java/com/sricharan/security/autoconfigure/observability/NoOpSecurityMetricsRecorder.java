package com.sricharan.security.autoconfigure.observability;

import com.sricharan.security.core.audit.SecurityAuditEventType;

/**
 * No-op metrics recorder used when MeterRegistry is not available.
 */
public class NoOpSecurityMetricsRecorder implements SecurityMetricsRecorder {

    @Override
    public void increment(SecurityAuditEventType type, String outcome) {
        // no-op
    }

    @Override
    public void recordRefreshLatencyNanos(long nanos, String outcome) {
        // no-op
    }
}
