package com.sricharan.security.autoconfigure.observability;

import com.sricharan.security.core.audit.SecurityAuditEventType;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;

import java.util.concurrent.TimeUnit;

/**
 * Micrometer-backed security metrics.
 */
public class MicrometerSecurityMetricsRecorder implements SecurityMetricsRecorder {

    private final MeterRegistry meterRegistry;

    public MicrometerSecurityMetricsRecorder(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    @Override
    public void increment(SecurityAuditEventType type, String outcome) {
        Counter.builder("security.audit.events")
                .tag("type", type.name())
                .tag("outcome", outcome)
                .register(meterRegistry)
                .increment();
    }

    @Override
    public void recordRefreshLatencyNanos(long nanos, String outcome) {
        Timer.builder("security.auth.refresh.latency")
                .tag("outcome", outcome)
                .register(meterRegistry)
                .record(nanos, TimeUnit.NANOSECONDS);
    }
}
