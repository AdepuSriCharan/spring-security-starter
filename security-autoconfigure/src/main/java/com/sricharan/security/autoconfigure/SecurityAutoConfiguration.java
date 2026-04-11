package com.sricharan.security.autoconfigure;

import com.sricharan.security.autoconfigure.adapter.JwtAuthenticationAdapter;
import com.sricharan.security.autoconfigure.adapter.SpringSecurityAuthenticationAdapter;
import com.sricharan.security.autoconfigure.aspect.AuthorizationAspect;
import com.sricharan.security.autoconfigure.config.SecurityProperties;
import com.sricharan.security.autoconfigure.controller.AuthController;
import com.sricharan.security.autoconfigure.filter.JwtAuthenticationFilter;
import com.sricharan.security.autoconfigure.filter.SecurityContextFilter;
import com.sricharan.security.autoconfigure.handler.JsonAccessDeniedHandler;
import com.sricharan.security.autoconfigure.handler.JsonAuthenticationEntryPoint;
import com.sricharan.security.autoconfigure.handler.SecurityExceptionHandler;
import com.sricharan.security.autoconfigure.jwt.JwtProperties;
import com.sricharan.security.autoconfigure.jwt.JwtService;
import com.sricharan.security.autoconfigure.observability.JsonSecurityAuditSink;
import com.sricharan.security.autoconfigure.observability.MicrometerSecurityMetricsRecorder;
import com.sricharan.security.autoconfigure.observability.NoOpSecurityMetricsRecorder;
import com.sricharan.security.autoconfigure.observability.SecurityEventRecorder;
import com.sricharan.security.autoconfigure.observability.SecurityMetricsRecorder;
import com.sricharan.security.autoconfigure.token.InMemoryRefreshTokenStore;
import com.sricharan.security.core.account.UserAccountProvider;
import com.sricharan.security.core.adapter.AuthenticationAdapter;
import com.sricharan.security.core.audit.SecurityAuditSink;
import com.sricharan.security.core.authorization.AuthorizationManager;
import com.sricharan.security.core.authorization.DefaultAuthorizationManager;
import com.sricharan.security.core.config.AuthMode;
import com.sricharan.security.core.token.RefreshTokenStore;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.ClassUtils;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;

/**
 * Auto-configuration for the Spring Security Explainer library.
 *
 * <p>This is the central configuration class that bootstraps all security infrastructure.
 * Every bean uses {@code @ConditionalOnMissingBean}, allowing applications to override
 * any component by declaring their own bean of the same type.
 *
 * <h3>Authentication Modes</h3>
 * <p>The library supports three authentication modes, controlled by the
 * {@code security.auth-mode} property in {@code application.properties}:
 *
 * <table border="1" cellpadding="5">
 *   <tr><th>Mode</th><th>Property Value</th><th>Description</th></tr>
 *   <tr>
 *     <td><b>INTERNAL</b></td>
 *     <td>{@code security.auth-mode=INTERNAL}</td>
 *     <td>Default. Built-in JWT authentication with {@code /login}, {@code /refresh},
 *         and {@code /logout} endpoints. Requires {@code security.jwt.secret}.</td>
 *   </tr>
 *   <tr>
 *     <td><b>OAUTH2</b></td>
 *     <td>{@code security.auth-mode=OAUTH2}</td>
 *     <td>Delegates to Spring's OAuth2 Resource Server. Validates Bearer JWTs from
 *         any OIDC provider (Auth0, Azure AD, Okta, etc.). Requires
 *         {@code spring.security.oauth2.resourceserver.jwt.issuer-uri}.</td>
 *   </tr>
 *   <tr>
 *     <td><b>KEYCLOAK</b></td>
 *     <td>{@code security.auth-mode=KEYCLOAK}</td>
 *     <td>Like OAUTH2, but with automatic extraction of Keycloak's nested
 *         {@code realm_access.roles} and {@code resource_access.&lt;client&gt;.roles}.
 *         Requires {@code spring.security.oauth2.resourceserver.jwt.issuer-uri}
 *         and optionally {@code security.keycloak.client-id}.</td>
 *   </tr>
 * </table>
 *
 * <h3>Filter Chain Architecture</h3>
 * <ul>
 *   <li><b>INTERNAL:</b> JwtAuthenticationFilter → SecurityContextFilter → Controller</li>
 *   <li><b>OAUTH2/KEYCLOAK:</b> BearerTokenAuthenticationFilter (Spring) → SecurityContextFilter → Controller</li>
 * </ul>
 *
 * <p>OAUTH2 and KEYCLOAK mode beans are isolated in {@link ExternalProviderAutoConfiguration}
 * to prevent {@code ClassNotFoundException} when {@code spring-boot-starter-oauth2-resource-server}
 * is not on the classpath.
 *
 * @see SecurityProperties
 * @see JwtProperties
 * @see AuthMode
 * @see ExternalProviderAutoConfiguration
 */
@AutoConfiguration
@EnableConfigurationProperties({JwtProperties.class, SecurityProperties.class})
public class SecurityAutoConfiguration {

    private final SecurityProperties securityProperties;
    private final Environment environment;

    public SecurityAutoConfiguration(SecurityProperties securityProperties, Environment environment) {
        this.securityProperties = securityProperties;
        this.environment = environment;
    }

    /**
     * Validates that external provider configuration is present when OAUTH2 or KEYCLOAK
     * mode is active. Without an {@code issuer-uri} or {@code jwk-set-uri}, every request
     * would fail at runtime with a cryptic error.
     */
    @PostConstruct
    public void validateExternalProviderConfig() {
        AuthMode mode = securityProperties.getAuthMode();
        if (mode == AuthMode.OAUTH2 || mode == AuthMode.KEYCLOAK) {
            String issuerUri = environment.getProperty(
                    "spring.security.oauth2.resourceserver.jwt.issuer-uri");
            String jwkSetUri = environment.getProperty(
                    "spring.security.oauth2.resourceserver.jwt.jwk-set-uri");
            if ((issuerUri == null || issuerUri.isBlank())
                    && (jwkSetUri == null || jwkSetUri.isBlank())) {
                throw new IllegalStateException(
                        "security.auth-mode=" + mode + " requires either:\n"
                        + "  spring.security.oauth2.resourceserver.jwt.issuer-uri=<your-idp-url>\n"
                        + "or\n"
                        + "  spring.security.oauth2.resourceserver.jwt.jwk-set-uri=<your-jwks-url>\n"
                        + "Configure one of these in application.properties.");
            }
        }

        if (mode == AuthMode.INTERNAL
                && securityProperties.getRefresh().getStoreMode() == SecurityProperties.RefreshStoreMode.REDIS) {
            boolean redisClassPresent = ClassUtils.isPresent(
                    "org.springframework.data.redis.core.StringRedisTemplate",
                    ClassUtils.getDefaultClassLoader());
            if (!redisClassPresent) {
                throw new IllegalStateException(
                        "security.refresh.store-mode=REDIS requires Redis support on the classpath.\n"
                                + "Add dependency: org.springframework.boot:spring-boot-starter-data-redis");
            }
        }
    }

    // ── Universal beans (active in all modes) ─────────────────────────────────

    @Bean
    @ConditionalOnMissingBean
    public AuthorizationManager authorizationManager() {
        return new DefaultAuthorizationManager();
    }

    @Bean
    @ConditionalOnMissingBean
    public SpringSecurityAuthenticationAdapter springSecurityAuthenticationAdapter() {
        return new SpringSecurityAuthenticationAdapter();
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityContextFilter securityContextFilter(List<AuthenticationAdapter> adapters) {
        return new SecurityContextFilter(adapters);
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthorizationAspect authorizationAspect(AuthorizationManager authorizationManager) {
        return new AuthorizationAspect(authorizationManager);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityExceptionHandler securityExceptionHandler(SecurityEventRecorder securityEventRecorder) {
        return new SecurityExceptionHandler(securityEventRecorder);
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthenticationEntryPoint authenticationEntryPoint(SecurityEventRecorder securityEventRecorder) {
        return new JsonAuthenticationEntryPoint(securityEventRecorder);
    }

    @Bean
    @ConditionalOnMissingBean
    public AccessDeniedHandler accessDeniedHandler(SecurityEventRecorder securityEventRecorder) {
        return new JsonAccessDeniedHandler(securityEventRecorder);
    }

    @Bean
    @ConditionalOnMissingBean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityAuditSink securityAuditSink(
            SecurityProperties securityProperties,
            ObjectProvider<ObjectMapper> objectMapperProvider) {
        if (!securityProperties.getSecurityEvents().isEnabled()) {
            return event -> {
                // no-op
            };
        }
        ObjectMapper objectMapper = objectMapperProvider.getIfAvailable(ObjectMapper::new);
        return new JsonSecurityAuditSink(objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityMetricsRecorder securityMetricsRecorder(ObjectProvider<MeterRegistry> meterRegistryProvider) {
        MeterRegistry meterRegistry = meterRegistryProvider.getIfAvailable();
        if (meterRegistry == null) {
            return new NoOpSecurityMetricsRecorder();
        }
        return new MicrometerSecurityMetricsRecorder(meterRegistry);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityEventRecorder securityEventRecorder(
            SecurityAuditSink securityAuditSink,
            SecurityMetricsRecorder securityMetricsRecorder) {
        return new SecurityEventRecorder(securityAuditSink, securityMetricsRecorder);
    }

    @Bean
    public FilterRegistrationBean<SecurityContextFilter> disableSecurityContextFilterAutoRegistration(
            SecurityContextFilter filter) {
        FilterRegistrationBean<SecurityContextFilter> reg = new FilterRegistrationBean<>(filter);
        reg.setEnabled(false);
        return reg;
    }

    // ── INTERNAL mode beans (default) ─────────────────────────────────────────

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "security", name = "auth-mode", havingValue = "INTERNAL", matchIfMissing = true)
    public JwtService jwtService(JwtProperties properties) {
        return new JwtService(properties);
    }

    @Bean
    @ConditionalOnProperty(prefix = "security", name = "auth-mode", havingValue = "INTERNAL", matchIfMissing = true)
    public AuthenticationAdapter jwtAuthenticationAdapter() {
        return new JwtAuthenticationAdapter();
    }

    @Bean
    @ConditionalOnProperty(prefix = "security", name = "auth-mode", havingValue = "INTERNAL", matchIfMissing = true)
    public JwtAuthenticationFilter jwtAuthenticationFilter(JwtService jwtService) {
        return new JwtAuthenticationFilter(jwtService);
    }

    @Bean
    @ConditionalOnProperty(prefix = "security", name = "auth-mode", havingValue = "INTERNAL", matchIfMissing = true)
    public FilterRegistrationBean<JwtAuthenticationFilter> disableJwtFilterAutoRegistration(
            JwtAuthenticationFilter filter) {
        FilterRegistrationBean<JwtAuthenticationFilter> reg = new FilterRegistrationBean<>(filter);
        reg.setEnabled(false);
        return reg;
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "security", name = "auth-mode", havingValue = "INTERNAL", matchIfMissing = true)
    @ConditionalOnExpression("'${security.refresh.store-mode:INMEMORY}'.equals('INMEMORY')")
    public RefreshTokenStore refreshTokenStore() {
        return new InMemoryRefreshTokenStore();
    }

    @Bean
    @ConditionalOnBean(UserAccountProvider.class)
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "security", name = "auth-mode", havingValue = "INTERNAL", matchIfMissing = true)
    public AuthController authController(
            ObjectProvider<UserAccountProvider> userAccountProviderRef,
            PasswordEncoder passwordEncoder,
            JwtService jwtService,
            RefreshTokenStore refreshTokenStore,
            SecurityEventRecorder securityEventRecorder) {
        return new AuthController(userAccountProviderRef, passwordEncoder, jwtService, refreshTokenStore, securityEventRecorder);
    }

    /**
     * Security filter chain for INTERNAL mode.
     *
     * <p>Filter order: {@link JwtAuthenticationFilter} validates the Bearer token and
     * populates {@code SecurityContextHolder}, then {@link SecurityContextFilter} bridges
     * it to {@link com.sricharan.security.core.context.SecurityUserContext}.
     *
     * <p>Public endpoints: {@code /login}, {@code /refresh}, {@code /logout} plus any
     * paths listed in {@code security.public-endpoints}.
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "security", name = "auth-mode", havingValue = "INTERNAL", matchIfMissing = true)
    public SecurityFilterChain internalSecurityFilterChain(
            HttpSecurity http,
            SecurityProperties securityProperties,
            AuthenticationEntryPoint authenticationEntryPoint,
            AccessDeniedHandler accessDeniedHandler,
            JwtAuthenticationFilter jwtAuthenticationFilter,
            SecurityContextFilter securityContextFilter) throws Exception {

        return buildBaseChain(http, securityProperties, authenticationEntryPoint, accessDeniedHandler,
                List.of("/login", "/refresh", "/logout"))
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(securityContextFilter, JwtAuthenticationFilter.class)
                .build();
    }

    // ── Shared filter chain builder ───────────────────────────────────────────

    /**
     * Constructs the base {@link HttpSecurity} configuration shared by all modes.
     *
     * <p>Configures: stateless sessions, CSRF disabled, JSON error handlers,
     * and public endpoint matchers.
     */
    static HttpSecurity buildBaseChain(
            HttpSecurity http,
            SecurityProperties securityProperties,
            AuthenticationEntryPoint authenticationEntryPoint,
            AccessDeniedHandler accessDeniedHandler,
            List<String> defaultPublicPaths) throws Exception {

        List<String> permitAll = new ArrayList<>(defaultPublicPaths);
        if (securityProperties.getPublicEndpoints() != null) {
            permitAll.addAll(securityProperties.getPublicEndpoints());
        }

        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .logout(AbstractHttpConfigurer::disable)
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler))
                .authorizeHttpRequests(auth -> {
                    if (!permitAll.isEmpty()) {
                        auth.requestMatchers(permitAll.toArray(new String[0])).permitAll();
                    }
                    auth.anyRequest().authenticated();
                });

        return http;
    }
}
