package com.sricharan.security.autoconfigure.aspect;

import com.sricharan.security.core.annotation.RequireOwner;
import com.sricharan.security.core.annotation.RequirePermission;
import com.sricharan.security.core.annotation.RequireRole;
import com.sricharan.security.core.authorization.AuthorizationManager;
import com.sricharan.security.core.context.SecurityUserContext;
import com.sricharan.security.core.exception.SecurityAuthorizationException;
import com.sricharan.security.core.user.AuthenticatedUser;
import com.sricharan.security.autoconfigure.util.SpelExpressionEvaluator;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;

import java.lang.reflect.Method;
import java.util.Collections;

/**
 * AOP aspect that intercepts controller methods annotated with
 * {@link RequireRole} or {@link RequirePermission} and delegates
 * authorization checks to the {@link AuthorizationManager}.
 *
 * <h3>Flow:</h3>
 * <pre>
 *   HTTP Request
 *    → Controller method
 *    → Aspect intercepts (this class)
 *    → Gets user from SecurityUserContext
 *    → Calls AuthorizationManager.checkRole / checkPermission
 *    → Allow or throw SecurityAuthorizationException
 * </pre>
 */
@Aspect
public class AuthorizationAspect {

    private final AuthorizationManager authorizationManager;
    private final SpelExpressionEvaluator spelEvaluator = new SpelExpressionEvaluator();

    public AuthorizationAspect(AuthorizationManager authorizationManager) {
        this.authorizationManager = authorizationManager;
    }

    /**
     * Intercept methods annotated with {@code @RequireRole}.
     */
    @Before("@annotation(requireRole)")
    public void checkRole(RequireRole requireRole) {
        AuthenticatedUser user = SecurityUserContext.requireCurrentUser();
        authorizationManager.checkRole(user, requireRole.value());
    }

    /**
     * Intercept methods annotated with {@code @RequirePermission}.
     */
    @Before("@annotation(requirePermission)")
    public void checkPermission(RequirePermission requirePermission) {
        AuthenticatedUser user = SecurityUserContext.requireCurrentUser();
        authorizationManager.checkPermission(user, requirePermission.value());
    }

    /**
     * Intercept methods annotated with {@code @RequireOwner}.
     */
    @Before("@annotation(requireOwner)")
    public void checkOwner(JoinPoint joinPoint, RequireOwner requireOwner) {
        AuthenticatedUser user = SecurityUserContext.requireCurrentUser();
        
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();
        
        String requiredOwnerId = spelEvaluator.evaluate(
                requireOwner.value(),
                method,
                joinPoint.getArgs()
        );

        if (requiredOwnerId == null || !requiredOwnerId.equals(user.getUserId())) {
            throw new SecurityAuthorizationException(
                    user.getUsername(),
                    new String[]{},
                    Collections.emptySet(),
                    SecurityAuthorizationException.AuthorizationType.OWNERSHIP,
                    requiredOwnerId
            );
        }
    }
}
