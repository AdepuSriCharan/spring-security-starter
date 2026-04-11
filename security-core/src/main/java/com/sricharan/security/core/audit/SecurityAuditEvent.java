package com.sricharan.security.core.audit;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Structured security audit event.
 */
public final class SecurityAuditEvent {

    private final Instant timestamp;
    private final SecurityAuditEventType type;
    private final String outcome;
    private final String userId;
    private final String username;
    private final Map<String, String> details;

    public SecurityAuditEvent(
            Instant timestamp,
            SecurityAuditEventType type,
            String outcome,
            String userId,
            String username,
            Map<String, String> details) {
        this.timestamp = timestamp;
        this.type = type;
        this.outcome = outcome;
        this.userId = userId;
        this.username = username;
        this.details = details == null
                ? Map.of()
                : Collections.unmodifiableMap(new LinkedHashMap<>(details));
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public SecurityAuditEventType getType() {
        return type;
    }

    public String getOutcome() {
        return outcome;
    }

    public String getUserId() {
        return userId;
    }

    public String getUsername() {
        return username;
    }

    public Map<String, String> getDetails() {
        return details;
    }
}
