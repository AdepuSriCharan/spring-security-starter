package com.sricharan.security.autoconfigure.observability;

import com.sricharan.security.core.audit.SecurityAuditEvent;
import com.sricharan.security.core.audit.SecurityAuditEventType;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityEventRecorderTest {

    @Test
    void recordPublishesAuditEventAndMetric() {
        AtomicReference<SecurityAuditEvent> captured = new AtomicReference<>();
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();

        SecurityEventRecorder recorder = new SecurityEventRecorder(
                captured::set,
                new MicrometerSecurityMetricsRecorder(meterRegistry));

        recorder.record(
                SecurityAuditEventType.LOGIN_SUCCESS,
                "SUCCESS",
                "user-1",
                "john",
                Map.of("method", "password"));

        SecurityAuditEvent event = captured.get();
        assertThat(event).isNotNull();
        assertThat(event.getType()).isEqualTo(SecurityAuditEventType.LOGIN_SUCCESS);
        assertThat(event.getOutcome()).isEqualTo("SUCCESS");
        assertThat(event.getUserId()).isEqualTo("user-1");
        assertThat(event.getUsername()).isEqualTo("john");
        assertThat(event.getDetails()).containsEntry("method", "password");

        double count = meterRegistry.get("security.audit.events")
                .tag("type", "LOGIN_SUCCESS")
                .tag("outcome", "SUCCESS")
                .counter()
                .count();
        assertThat(count).isEqualTo(1.0d);
    }

    @Test
    void refreshLatencyMetricIsRecorded() {
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        SecurityEventRecorder recorder = new SecurityEventRecorder(
                event -> {
                    // no-op
                },
                new MicrometerSecurityMetricsRecorder(meterRegistry));

        recorder.recordRefreshLatencyNanos(10_000_000L, "SUCCESS");

        double count = meterRegistry.get("security.auth.refresh.latency")
                .tag("outcome", "SUCCESS")
                .timer()
                .count();
        assertThat(count).isEqualTo(1.0d);
    }
}
