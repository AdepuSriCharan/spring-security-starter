package com.sricharan.security.core.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Restricts access to a controller method to the authenticated user who "owns"
 * the requested resource.
 *
 * <p>Uses Spring Expression Language (SpEL) to extract the resource ID
 * from the method parameters and compares it against the
 * {@link com.sricharan.security.core.user.AuthenticatedUser#getUserId()}.
 *
 * <p>Usage:
 * <pre>
 *   &#64;GetMapping("/users/{userId}/profile")
 *   &#64;RequireOwner("#userId")
 *   public Profile getProfile(&#64;PathVariable String userId) { ... }
 *
 *   &#64;PutMapping("/orders/{orderId}")
 *   &#64;RequireOwner("#orderDto.userId")
 *   public void updateOrder(&#64;PathVariable String orderId, &#64;RequestBody OrderDto orderDto) { ... }
 * </pre>
 *
 * <p>Intercepted by {@code AuthorizationAspect} in the autoconfigure module.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireOwner {

    /**
     * The SpEL expression to evaluate against the method parameters to find the owner ID.
     * Often just a parameter name prefixed with `#`, like `"#userId"`.
     */
    String value();
}
