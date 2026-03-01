package com.sricharan.security.core.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Restricts access to a controller method to users with at least one
 * of the specified permissions.
 *
 * <p>Usage:
 * <pre>
 *   &#64;PostMapping("/donors")
 *   &#64;RequirePermission("donor:create")
 *   public Donor createDonor(...) { ... }
 *
 *   &#64;DeleteMapping("/donors/{id}")
 *   &#64;RequirePermission({"donor:delete", "admin:all"})
 *   public void deleteDonor(...) { ... }
 * </pre>
 *
 * <p>Intercepted by {@code AuthorizationAspect} in the autoconfigure module.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RequirePermission {

    /**
     * One or more permission strings. The user must hold at least one.
     */
    String[] value();
}
