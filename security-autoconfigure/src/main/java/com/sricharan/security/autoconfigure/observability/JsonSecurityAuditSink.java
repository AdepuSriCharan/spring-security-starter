package com.sricharan.security.autoconfigure.observability;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sricharan.security.core.audit.SecurityAuditEvent;
import com.sricharan.security.core.audit.SecurityAuditSink;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Default JSON logger for security audit events.
 */
public class JsonSecurityAuditSink implements SecurityAuditSink {

    private static final Logger log = LoggerFactory.getLogger(JsonSecurityAuditSink.class);

    private final ObjectMapper objectMapper;

    public JsonSecurityAuditSink(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void publish(SecurityAuditEvent event) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("timestamp", event.getTimestamp().toString());
        payload.put("category", "SECURITY_AUDIT");
        payload.put("type", event.getType().name());
        payload.put("outcome", event.getOutcome());
        payload.put("userId", event.getUserId());
        payload.put("username", event.getUsername());
        payload.put("details", event.getDetails());

        try {
            log.info("{}", objectMapper.writeValueAsString(payload));
        } catch (JsonProcessingException e) {
            log.warn("Failed to serialize security audit event '{}': {}", event.getType(), e.getMessage());
        }
    }
}
