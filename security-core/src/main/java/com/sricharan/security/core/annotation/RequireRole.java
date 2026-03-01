package com.sricharan.security.core.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Restricts access to a controller method to users with at least one
 * of the specified roles.
 *
 * <p>Usage:
 * <pre>
 *   &#64;GetMapping("/admin/dashboard")
 *   &#64;RequireRole("ADMIN")
 *   public String adminDashboard() { ... }
 *
 *   &#64;GetMapping("/manage")
 *   &#64;RequireRole({"ADMIN", "MANAGER"})
 *   public String manage() { ... }
 * </pre>
 *
 * <p>Intercepted by {@code AuthorizationAspect} in the autoconfigure module.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireRole {

    /**
     * One or more role names. The user must hold at least one.
     */
    String[] value();
}
