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
import com.sricharan.security.autoconfigure.token.InMemoryRefreshTokenStore;
import com.sricharan.security.core.account.UserAccountProvider;
import com.sricharan.security.core.adapter.AuthenticationAdapter;
import com.sricharan.security.core.authorization.AuthorizationManager;
import com.sricharan.security.core.authorization.DefaultAuthorizationManager;
import com.sricharan.security.core.token.RefreshTokenStore;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
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
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.ArrayList;
import java.util.List;

/**
 * Auto-configuration for the Spring Security Explainer library.
 *
 * <p>Every bean uses {@code @ConditionalOnMissingBean} so applications
 * can override any component by declaring their own bean of the same type.
 *
 * @see SecurityProperties
 * @see JwtProperties
 */
@AutoConfiguration
@EnableConfigurationProperties({JwtProperties.class, SecurityProperties.class})
public class SecurityAutoConfiguration {

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
    public JwtService jwtService(JwtProperties properties) {
        return new JwtService(properties);
    }

    @Bean
    public AuthenticationAdapter jwtAuthenticationAdapter() {
        return new JwtAuthenticationAdapter();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(JwtService jwtService) {
        return new JwtAuthenticationFilter(jwtService);
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

    /**
     * Prevents double-invocation of {@link JwtAuthenticationFilter} by
     * disabling its servlet-level registration. The filter is only invoked
     * through the Spring Security filter chain.
     */
    @Bean
    public FilterRegistrationBean<JwtAuthenticationFilter> disableJwtFilterAutoRegistration(
            JwtAuthenticationFilter filter) {
        FilterRegistrationBean<JwtAuthenticationFilter> reg = new FilterRegistrationBean<>(filter);
        reg.setEnabled(false);
        return reg;
    }

    /**
     * Prevents double-invocation of {@link SecurityContextFilter} by
     * disabling its servlet-level registration.
     */
    @Bean
    public FilterRegistrationBean<SecurityContextFilter> disableSecurityContextFilterAutoRegistration(
            SecurityContextFilter filter) {
        FilterRegistrationBean<SecurityContextFilter> reg = new FilterRegistrationBean<>(filter);
        reg.setEnabled(false);
        return reg;
    }

    /**
     * Default {@link SecurityFilterChain} provided by the starter.
     *
     * <p>Override this bean to customise HTTP security rules, but ensure
     * the JWT and SecurityContext filters are inserted in the correct order.
     */
    @Bean
    @ConditionalOnMissingBean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            SecurityProperties securityProperties,
            AuthenticationEntryPoint authenticationEntryPoint,
            AccessDeniedHandler accessDeniedHandler,
            JwtAuthenticationFilter jwtAuthenticationFilter,
            SecurityContextFilter securityContextFilter) throws Exception {

        List<String> permitAll = new ArrayList<>(List.of("/login", "/refresh", "/logout"));
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
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(permitAll.toArray(new String[0])).permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(securityContextFilter, JwtAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    @ConditionalOnMissingBean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @ConditionalOnMissingBean
    public RefreshTokenStore refreshTokenStore() {
        return new InMemoryRefreshTokenStore();
    }

    @Bean
    @ConditionalOnBean(UserAccountProvider.class)
    @ConditionalOnMissingBean
    public AuthController authController(
            ObjectProvider<UserAccountProvider> userAccountProviderRef,
            PasswordEncoder passwordEncoder,
            JwtService jwtService,
            RefreshTokenStore refreshTokenStore) {
        return new AuthController(userAccountProviderRef, passwordEncoder, jwtService, refreshTokenStore);
    }
}
