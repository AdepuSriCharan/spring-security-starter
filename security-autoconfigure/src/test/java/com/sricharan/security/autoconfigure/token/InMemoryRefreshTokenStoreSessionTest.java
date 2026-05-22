package com.sricharan.security.autoconfigure.token;

import com.sricharan.security.core.token.RefreshSession;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class InMemoryRefreshTokenStoreSessionTest {

    @Test
    void listActiveSessionsReturnsOnlyActiveForUser() {
        InMemoryRefreshTokenStore store = new InMemoryRefreshTokenStore();
        store.store("user-1", "token-a", Instant.now().plusSeconds(60));
        store.store("user-1", "token-b", Instant.now().plusSeconds(120));
        store.store("user-2", "token-c", Instant.now().plusSeconds(60));
        store.revoke("token-b");

        List<RefreshSession> sessions = store.listActiveSessions("user-1");

        assertThat(sessions).hasSize(1);
        assertThat(sessions.get(0).sessionId()).isEqualTo("token-a");
    }

    @Test
    void revokeSessionRevokesOnlyMatchingUserSession() {
        InMemoryRefreshTokenStore store = new InMemoryRefreshTokenStore();
        store.store("user-1", "token-a", Instant.now().plusSeconds(60));

        assertThat(store.revokeSession("user-2", "token-a")).isFalse();
        assertThat(store.revokeSession("user-1", "missing")).isFalse();
        assertThat(store.revokeSession("user-1", "token-a")).isTrue();
        assertThat(store.revokeSession("user-1", "token-a")).isFalse();
        assertThat(store.isValid("token-a")).isFalse();
    }
}
