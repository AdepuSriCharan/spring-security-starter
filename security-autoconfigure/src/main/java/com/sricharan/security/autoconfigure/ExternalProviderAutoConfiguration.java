package com.sricharan.security.autoconfigure;

import com.sricharan.security.autoconfigure.adapter.KeycloakAuthenticationAdapter;
import com.sricharan.security.autoconfigure.adapter.OAuth2AuthenticationAdapter;
import com.sricharan.security.autoconfigure.config.SecurityProperties;
import com.sricharan.security.autoconfigure.filter.SecurityContextFilter;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.util.List;

/**
 * Auto-configuration for OAUTH2 and KEYCLOAK authentication modes.
 *
 * <p>This class is loaded <b>only when</b> {@code spring-boot-starter-oauth2-resource-server}
 * is on the classpath (guarded by {@link ConditionalOnClass}). This prevents
 * {@code ClassNotFoundException} in INTERNAL mode when the OAuth2 dependency is absent.
 *
 * <h3>OAUTH2 Mode</h3>
 * <p>Delegates JWT validation to Spring's OAuth2 Resource Server.
 * Claims are mapped to {@link com.sricharan.security.core.user.AuthenticatedUser} using
 * configurable claim names ({@code security.oauth2.username-claim}, etc.):
 * <pre>
 * security.auth-mode=OAUTH2
 * spring.security.oauth2.resourceserver.jwt.issuer-uri=https://your-idp/...
 * # Optional claim overrides:
 * security.oauth2.username-claim=preferred_username
 * security.oauth2.roles-claim=roles
 * security.oauth2.permissions-claim=permissions
 * </pre>
 *
 * <h3>KEYCLOAK Mode</h3>
 * <p>Extends OAUTH2 mode with automatic extraction of Keycloak's nested
 * {@code realm_access.roles} and {@code resource_access.<client>.roles}:
 * <pre>
 * security.auth-mode=KEYCLOAK
 * spring.security.oauth2.resourceserver.jwt.issuer-uri=http://localhost:9090/realms/my-realm
 * security.keycloak.client-id=my-app
 * # Optional overrides (defaults match Keycloak's standard structure):
 * security.keycloak.realm-access-claim=realm_access
 * security.keycloak.resource-access-claim=resource_access
 * security.keycloak.roles-key=roles
 * </pre>
 *
 * @see SecurityAutoConfiguration
 * @see OAuth2AuthenticationAdapter
 * @see KeycloakAuthenticationAdapter
 */
@AutoConfiguration(after = SecurityAutoConfiguration.class)
@ConditionalOnClass(BearerTokenAuthenticationFilter.class)
public class ExternalProviderAutoConfiguration {

    // ── OAUTH2 mode beans ─────────────────────────────────────────────────────

    @Bean
    @ConditionalOnMissingBean(OAuth2AuthenticationAdapter.class)
    @ConditionalOnProperty(prefix = "security", name = "auth-mode", havingValue = "OAUTH2")
    public OAuth2AuthenticationAdapter oauth2AuthenticationAdapter(SecurityProperties securityProperties) {
        return new OAuth2AuthenticationAdapter(securityProperties);
    }

    /**
     * Security filter chain for OAUTH2 mode.
     *
     * <p>Delegates JWT validation to Spring's {@code oauth2ResourceServer().jwt()} support.
     * The {@link SecurityContextFilter} runs <b>after</b> {@link BearerTokenAuthenticationFilter}
     * to ensure the {@code Authentication} is already populated in {@code SecurityContextHolder}.
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

        return SecurityAutoConfiguration
                .buildBaseChain(http, securityProperties, authenticationEntryPoint,
                        accessDeniedHandler, List.of())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> {}))
                .addFilterAfter(securityContextFilter, BearerTokenAuthenticationFilter.class)
                .build();
    }

    // ── KEYCLOAK mode beans ───────────────────────────────────────────────────

    @Bean
    @ConditionalOnMissingBean(KeycloakAuthenticationAdapter.class)
    @ConditionalOnProperty(prefix = "security", name = "auth-mode", havingValue = "KEYCLOAK")
    public KeycloakAuthenticationAdapter keycloakAuthenticationAdapter(SecurityProperties securityProperties) {
        return new KeycloakAuthenticationAdapter(securityProperties);
    }

    /**
     * Security filter chain for KEYCLOAK mode.
     *
     * <p>Same as OAUTH2 but paired with {@link KeycloakAuthenticationAdapter} which
     * extracts roles from Keycloak's nested {@code realm_access} and {@code resource_access} claims.
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

        return SecurityAutoConfiguration
                .buildBaseChain(http, securityProperties, authenticationEntryPoint,
                        accessDeniedHandler, List.of())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> {}))
                .addFilterAfter(securityContextFilter, BearerTokenAuthenticationFilter.class)
                .build();
    }
}
