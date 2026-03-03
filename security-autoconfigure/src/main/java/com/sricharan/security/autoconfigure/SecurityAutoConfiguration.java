package com.sricharan.security.autoconfigure;

import com.sricharan.security.autoconfigure.adapter.JwtAuthenticationAdapter;
import com.sricharan.security.autoconfigure.adapter.KeycloakAuthenticationAdapter;
import com.sricharan.security.autoconfigure.adapter.OAuth2AuthenticationAdapter;
import com.sricharan.security.autoconfigure.adapter.SpringSecurityAuthenticationAdapter;
import com.sricharan.security.autoconfigure.aspect.AuthorizationAspect;
import com.sricharan.security.autoconfigure.config.SecurityProperties;
import com.sricharan.security.core.config.AuthMode;
import org.springframework.core.env.Environment;
import com.sricharan.security.autoconfigure.controller.AuthController;
import com.sricharan.security.autoconfigure.filter.JwtAuthenticationFilter;
import com.sricharan.security.autoconfigure.filter.SecurityContextFilter;
import com.sricharan.security.autoconfigure.handler.JsonAccessDeniedHandler;
import com.sricharan.security.autoconfigure.handler.JsonAuthenticationEntryPoint;
import com.sricharan.security.autoconfigure.handler.SecurityExceptionHandler;
import com.sricharan.security.autoconfigure.jwt.JwtProperties;
import com.sricharan.security.autoconfigure.jwt.JwtService;
import com.sricharan.security.autoconfigure.token.InMemoryRefreshTokenStore;
import com.sricharan.security.core.account.UserAccountProvider;
import com.sricharan.security.core.adapter.AuthenticationAdapter;
import com.sricharan.security.core.authorization.AuthorizationManager;
import com.sricharan.security.core.authorization.DefaultAuthorizationManager;
import com.sricharan.security.core.token.RefreshTokenStore;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.ArrayList;
import java.util.List;

/**
 * Auto-configuration for the Spring Security Explainer library.
 *
 * <p>Every bean uses {@code @ConditionalOnMissingBean} so applications
 * can override any component by declaring their own bean of the same type.
 *
 * <p>Authentication mode is controlled by {@code security.auth-mode}:
 * <ul>
 *   <li>{@code INTERNAL} (default) — built-in JWT. /login, /refresh, /logout active.</li>
 *   <li>{@code OAUTH2} — Spring OAuth2 Resource Server. /login not provided.</li>
 *   <li>{@code KEYCLOAK} — OAuth2 with Keycloak nested-claim extraction.</li>
 * </ul>
 *
 * @see SecurityProperties
 * @see JwtProperties
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
     * Fail fast if OAUTH2 or KEYCLOAK mode is active but no token validation
     * endpoint has been configured. Without issuer-uri or jwk-set-uri, every
     * request will fail at runtime with a cryptic error.
     */
    @PostConstruct
    public void validateExternalProviderConfig() {
        AuthMode mode = securityProperties.getAuthMode();
        if (mode == AuthMode.OAUTH2 || mode == AuthMode.KEYCLOAK) {
            String issuerUri  = environment.getProperty("spring.security.oauth2.resourceserver.jwt.issuer-uri");
            String jwkSetUri  = environment.getProperty("spring.security.oauth2.resourceserver.jwt.jwk-set-uri");
            if ((issuerUri == null || issuerUri.isBlank()) && (jwkSetUri == null || jwkSetUri.isBlank())) {
                throw new IllegalStateException(
                        "security.auth-mode=" + mode + " requires either:\n" +
                        "  spring.security.oauth2.resourceserver.jwt.issuer-uri=https://<your-idp>/realms/<realm>\n" +
                        "or\n" +
                        "  spring.security.oauth2.resourceserver.jwt.jwk-set-uri=https://<your-idp>/realms/<realm>/protocol/openid-connect/certs\n" +
                        "Configure one of these in application.properties to allow token validation.");
            }
        }
    }

    // ── Universal beans (all modes) ───────────────────────────────────────────

    @Bean
    @ConditionalOnMissingBean
    public AuthorizationManager authorizationManager() {
        return new DefaultAuthorizationManager();
    }

    @Bean
    @ConditionalOnMissingBean(AuthenticationAdapter.class)
    public SpringSecurityAuthenticationAdapter springSecurityAuthenticationAdapter() {
        return new SpringSecurityAuthenticationAdapter();
    }

    @Bean
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
    public SecurityExceptionHandler securityExceptionHandler() {
        return new SecurityExceptionHandler();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return new JsonAuthenticationEntryPoint();
    }

    @Bean
    @ConditionalOnMissingBean
    public AccessDeniedHandler accessDeniedHandler() {
        return new JsonAccessDeniedHandler();
    }

    @Bean
    @ConditionalOnMissingBean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public FilterRegistrationBean<SecurityContextFilter> disableSecurityContextFilterAutoRegistration(
            SecurityContextFilter filter) {
        FilterRegistrationBean<SecurityContextFilter> reg = new FilterRegistrationBean<>(filter);
        reg.setEnabled(false);
        return reg;
    }

    // ── INTERNAL mode beans (default) ────────────────────────────────────────

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
            RefreshTokenStore refreshTokenStore) {
        return new AuthController(userAccountProviderRef, passwordEncoder, jwtService, refreshTokenStore);
    }

    /**
     * Security filter chain for INTERNAL mode.
     * Uses the built-in JwtAuthenticationFilter.
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

    // ── OAUTH2 mode beans ─────────────────────────────────────────────────────

    @Bean
    @ConditionalOnMissingBean(OAuth2AuthenticationAdapter.class)
    @ConditionalOnProperty(prefix = "security", name = "auth-mode", havingValue = "OAUTH2")
    public OAuth2AuthenticationAdapter oauth2AuthenticationAdapter() {
        return new OAuth2AuthenticationAdapter(securityProperties);
    }

    /**
     * Security filter chain for OAUTH2 mode.
     * Delegates token validation to Spring's OAuth2 Resource Server.
     * SecurityContextFilter runs after BearerTokenAuthenticationFilter so the
     * Authentication is already populated in SecurityContextHolder.
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "security", name = "auth-mode", havingValue = "OAUTH2")
    public SecurityFilterChain oauth2SecurityFilterChain(
            HttpSecurity http,
            SecurityProperties securityProperties,
            AuthenticationEntryPoint authenticationEntryPoint,
            AccessDeniedHandler accessDeniedHandler,
            SecurityContextFilter securityContextFilter) throws Exception {

        return buildBaseChain(http, securityProperties, authenticationEntryPoint, accessDeniedHandler,
                List.of())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> {}))
                .addFilterAfter(securityContextFilter, BearerTokenAuthenticationFilter.class)
                .build();
    }

    // ── KEYCLOAK mode beans ───────────────────────────────────────────────────

    @Bean
    @ConditionalOnMissingBean(KeycloakAuthenticationAdapter.class)
    @ConditionalOnProperty(prefix = "security", name = "auth-mode", havingValue = "KEYCLOAK")
    public KeycloakAuthenticationAdapter keycloakAuthenticationAdapter() {
        return new KeycloakAuthenticationAdapter(securityProperties);
    }

    /**
     * Security filter chain for KEYCLOAK mode.
     * Same as OAUTH2 but uses KeycloakAuthenticationAdapter for claim extraction.
     * SecurityContextFilter runs after BearerTokenAuthenticationFilter so the
     * Authentication is already populated in SecurityContextHolder.
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "security", name = "auth-mode", havingValue = "KEYCLOAK")
    public SecurityFilterChain keycloakSecurityFilterChain(
            HttpSecurity http,
            SecurityProperties securityProperties,
            AuthenticationEntryPoint authenticationEntryPoint,
            AccessDeniedHandler accessDeniedHandler,
            SecurityContextFilter securityContextFilter) throws Exception {

        return buildBaseChain(http, securityProperties, authenticationEntryPoint, accessDeniedHandler,
                List.of())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> {}))
                .addFilterAfter(securityContextFilter, BearerTokenAuthenticationFilter.class)
                .build();
    }

    // ── Shared filter chain builder ───────────────────────────────────────────

    private HttpSecurity buildBaseChain(
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
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .logout(AbstractHttpConfigurer::disable)
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                )
                .authorizeHttpRequests(auth -> {
                    if (!permitAll.isEmpty()) {
                        auth.requestMatchers(permitAll.toArray(new String[0])).permitAll();
                    }
                    auth.anyRequest().authenticated();
                });

        return http;
    }
}

