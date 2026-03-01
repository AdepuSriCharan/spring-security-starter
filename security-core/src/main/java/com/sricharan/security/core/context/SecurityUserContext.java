package com.sricharan.security.core.context;

import com.sricharan.security.core.user.AuthenticatedUser;

/**
 * Thread-local holder for the current {@link AuthenticatedUser}.
 *
 * <p>Set by the {@code SecurityContextFilter} at the start of each request
 * and cleared when the request completes.
 *
 * <p>Usage in application code:
 * <pre>
 *   AuthenticatedUser user = SecurityUserContext.getCurrentUser();
 * </pre>
 *
 * <p><strong>⚠ THREAD SAFETY WARNING:</strong>
 * This context uses a plain {@link ThreadLocal} and is therefore <b>only available
 * on the original request thread</b>. The user context will NOT be propagated to:
 * <ul>
 *   <li>{@code @Async} methods</li>
 *   <li>{@code CompletableFuture} / thread pool tasks</li>
 *   <li>Reactive / WebFlux pipelines</li>
 *   <li>Virtual threads (Project Loom)</li>
 * </ul>
 *
 * <p>If you need context propagation across threads, consider using
 * {@link InheritableThreadLocal} (with caution — pooled threads reuse context)
 * or a context-propagation library like Micrometer Context Propagation.
 */
public final class SecurityUserContext {

    private static final ThreadLocal<AuthenticatedUser> CONTEXT = new ThreadLocal<>();

    private SecurityUserContext() {
        // utility class
    }

    /**
     * Get the authenticated user for the current request.
     *
     * @return the current user, or {@code null} if not authenticated
     */
    public static AuthenticatedUser getCurrentUser() {
        return CONTEXT.get();
    }

    /**
     * Get the authenticated user, throwing if not present.
     *
     * @return the current user
     * @throws IllegalStateException if no user is set
     */
    public static AuthenticatedUser requireCurrentUser() {
        AuthenticatedUser user = CONTEXT.get();
        if (user == null) {
            throw new IllegalStateException(
                    "No authenticated user in SecurityUserContext. " +
                    "Ensure the request passed through SecurityContextFilter.");
        }
        return user;
    }

    /**
     * Set the authenticated user for the current request.
     * Called by the SecurityContextFilter.
     */
    public static void setCurrentUser(AuthenticatedUser user) {
        CONTEXT.set(user);
    }

    /**
     * Clear the context. Must be called at the end of each request
     * to prevent ThreadLocal leaks.
     */
    public static void clear() {
        CONTEXT.remove();
    }
}
