package com.sricharan.security.test;

import com.sricharan.security.autoconfigure.filter.JwtAuthenticationFilter;
import com.sricharan.security.autoconfigure.filter.SecurityContextFilter;
import com.sricharan.security.autoconfigure.handler.JsonAccessDeniedHandler;
import com.sricharan.security.autoconfigure.handler.JsonAuthenticationEntryPoint;
import com.sricharan.security.core.account.UserAccount;
import com.sricharan.security.core.account.UserAccountProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Test security configuration with in-memory users.
 *
 * <p>Users:
 * <ul>
 *   <li>{@code admin / admin} — roles: ADMIN, USER</li>
 *   <li>{@code user / user} — roles: USER</li>
 * </ul>
 */
@Configuration
public class TestSecurityConfig {

    @Bean
    public UserAccountProvider userAccountProvider(PasswordEncoder encoder) {
        
        UserAccount admin = new SimpleUserAccount(
                "admin-id", "admin", encoder.encode("admin"),
                Set.of("ADMIN", "USER"), Set.of("system:manage"));
                
        UserAccount user = new SimpleUserAccount(
                "user-id", "user", encoder.encode("user"),
                Set.of("USER"), Set.of("donor:create"));
                
        UserAccount john = new SimpleUserAccount(
                "john", "john", encoder.encode("password"),
                Set.of("USER"), Set.of());

        Map<String, UserAccount> users = Map.of(
                "admin", admin,
                "user", user,
                "john", john
        );

        return username -> Optional.ofNullable(users.get(username));
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            JwtAuthenticationFilter jwtAuthenticationFilter,
            SecurityContextFilter securityContextFilter) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .logout(AbstractHttpConfigurer::disable)
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(new JsonAuthenticationEntryPoint())
                        .accessDeniedHandler(new JsonAccessDeniedHandler())
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/public").permitAll()
                        .requestMatchers("/login", "/refresh", "/logout").permitAll()
                        .anyRequest().authenticated()
                )
                .httpBasic(basic -> {})
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(securityContextFilter, JwtAuthenticationFilter.class);

        return http.build();
    }

    private static class SimpleUserAccount implements UserAccount {
        private final String id;
        private final String username;
        private final String password;
        private final Set<String> roles;
        private final Set<String> permissions;

        public SimpleUserAccount(String id, String username, String password, Set<String> roles, Set<String> permissions) {
            this.id = id;
            this.username = username;
            this.password = password;
            this.roles = roles;
            this.permissions = permissions;
        }

        @Override public String getId() { return id; }
        @Override public String getUsername() { return username; }
        @Override public String getPassword() { return password; }
        @Override public Set<String> getRoles() { return roles; }
        @Override public Set<String> getPermissions() { return permissions; }
    }
}
