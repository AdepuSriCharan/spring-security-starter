package com.sricharan.security.core.audit;

/**
 * Extension point for consuming security audit events.
 */
@FunctionalInterface
public interface SecurityAuditSink {

    /**
     * Publish a security audit event.
     */
    void publish(SecurityAuditEvent event);
}
