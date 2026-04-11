package com.sricharan.security.core.audit;

/**
 * Built-in security audit event types emitted by the starter.
 */
public enum SecurityAuditEventType {
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    REFRESH_SUCCESS,
    REFRESH_FAILURE,
    REFRESH_REPLAY_DETECTED,
    LOGOUT,
    SESSION_REVOKED,
    ACCESS_DENIED,
    UNAUTHORIZED
}
