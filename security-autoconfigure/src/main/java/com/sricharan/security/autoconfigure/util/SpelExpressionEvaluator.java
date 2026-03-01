package com.sricharan.security.autoconfigure.util;

import org.springframework.context.expression.MethodBasedEvaluationContext;
import org.springframework.core.DefaultParameterNameDiscoverer;
import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;

import java.lang.reflect.Method;

/**
 * Utility to evaluate Spring Expression Language (SpEL) expressions
 * against a method's arguments.
 */
public class SpelExpressionEvaluator {

    private final ExpressionParser parser = new SpelExpressionParser();
    private final ParameterNameDiscoverer parameterNameDiscoverer = new DefaultParameterNameDiscoverer();

    /**
     * Evaluates a SpEL expression dynamically against the provided method and arguments.
     *
     * @param expression The SpEL expression (e.g. "#userId" or "#dto.id")
     * @param method     The target method
     * @param args       The arguments passed to the method at runtime
     * @return The evaluated result as a String, or null
     */
    public String evaluate(String expression, Method method, Object[] args) {
        EvaluationContext context = new MethodBasedEvaluationContext(
                null,
                method,
                args,
                parameterNameDiscoverer);

        Object result = parser.parseExpression(expression).getValue(context);
        return result != null ? result.toString() : null;
    }
}
