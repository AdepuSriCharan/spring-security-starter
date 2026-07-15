# Customization & Extension Points

Spring Security Explainer is designed to be fully replaceable at every layer. All default beans are registered with `@ConditionalOnMissingBean`, meaning you can override any component by declaring your own `@Bean` of the same type.

---

## Overview of Extension Points

| Interface / Type | Default Implementation | Override Reason |
|---|---|---|
| `UserAccountProvider` | *(must implement)* | Wire your user database |
| `UserAccount` | *(must implement)* | Describe your user model |
| `AuthorizationManager` | `DefaultAuthorizationManager` | Hierarchical RBAC, ABAC, policy engines |
| `RefreshTokenStore` | `InMemoryRefreshTokenStore` | JPA, DynamoDB, or any persistence backend |
| `PasswordEncoder` | `BCryptPasswordEncoder` | Argon2, SCrypt, etc. |
| `SecurityAuditSink` | `JsonSecurityAuditSink` | Kafka, SIEM, Splunk, custom routing |
| `AuthenticationAdapter` | Mode-specific defaults | Custom authentication source |
| `SecurityFilterChain` | Mode-specific defaults | Full custom filter chain |
| `SecurityContextFilter` | `SecurityContextFilter` | Custom context propagation |
| `AuthenticationEntryPoint` | `JsonAuthenticationEntryPoint` | Custom 401 response format |
| `AccessDeniedHandler` | `JsonAccessDeniedHandler` | Custom 403 response format |

---

## 1. Implementing `UserAccountProvider`

This is the **only required** implementation. The library calls `findByUsername` during the `/login` flow.

```java
@Service
public class JpaUserAccountProvider implements UserAccountProvider {

    private final UserRepository userRepository;

    public JpaUserAccountProvider(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public Optional<UserAccount> findByUsername(String username) {
        return userRepository.findByUsername(username)
                .map(user -> new UserAccount() {
                    @Override public String getId() { return user.getId(); }
                    @Override public String getUsername() { return user.getUsername(); }
                    @Override public String getPassword() { return user.getPasswordHash(); }
                    @Override public Set<String> getRoles() {
                        return user.getRoles().stream()
                               .map(Role::getName).collect(Collectors.toSet());
                    }
                    @Override public Set<String> getPermissions() {
                        return user.getPermissions();
                    }
                });
    }
}
```

Alternatively, implement the `UserAccount` interface directly on your JPA entity:

```java
@Entity
public class User implements UserAccount {

    @Id
    private String id;
    private String username;
    private String passwordHash;

    @ManyToMany
    private Set<Role> roles;

    private Set<String> permissions;

    @Override public String getId() { return id; }
    @Override public String getUsername() { return username; }
    @Override public String getPassword() { return passwordHash; }
    @Override public Set<String> getRoles() {
        return roles.stream().map(Role::getName).collect(Collectors.toSet());
    }
    @Override public Set<String> getPermissions() { return permissions; }
}
```

---

## 2. Custom `RefreshTokenStore`

Implement `RefreshTokenStore` to back refresh tokens with any persistence technology:

```java
@Service
public class JpaRefreshTokenStore implements RefreshTokenStore {

    private final RefreshTokenRepository repository;

    @Override
    public void store(String userId, String tokenHash, Instant expiresAt) {
        repository.save(new JpaRefreshToken(userId, tokenHash, expiresAt, false));
    }

    @Override
    public boolean isValid(String tokenHash) {
        return repository.findByTokenHash(tokenHash)
            .map(t -> !t.isRevoked() && t.getExpiresAt().isAfter(Instant.now()))
            .orElse(false);
    }

    @Override
    public boolean consumeForRotation(String tokenHash) {
        // Must be atomic — use a database transaction with SELECT FOR UPDATE
        return repository.findByTokenHashForUpdate(tokenHash)
            .filter(t -> !t.isRevoked() && t.getExpiresAt().isAfter(Instant.now()))
            .map(t -> {
                t.setRevoked(true);
                repository.save(t);
                return true;
            })
            .orElse(false);
    }

    @Override
    public void revoke(String tokenHash) {
        repository.findByTokenHash(tokenHash).ifPresent(t -> {
            t.setRevoked(true);
            repository.save(t);
        });
    }

    @Override
    public void revokeAllForUser(String userId) {
        repository.revokeAllByUserId(userId);
    }
}
```

> **Security contract:** Always store only the SHA-256 hash of the raw token, never the raw token itself. The library passes pre-hashed values via `TokenHashUtil.sha256()` before calling `store()`.

---

## 3. Custom `SecurityAuditSink`

Route security audit events to any destination:

```java
// Kafka example
@Service
public class KafkaSecurityAuditSink implements SecurityAuditSink {

    private final KafkaTemplate<String, String> kafkaTemplate;
    private final ObjectMapper objectMapper;

    @Override
    public void publish(SecurityAuditEvent event) {
        try {
            String payload = objectMapper.writeValueAsString(event);
            kafkaTemplate.send("security-audit-events", event.getType().name(), payload);
        } catch (JsonProcessingException e) {
            // log and continue — never throw from an audit sink
        }
    }
}

// Disabling audit events entirely
security.security-events.enabled=false
```

---

## 4. Custom `AuthorizationManager`

Replace the default flat set-intersection logic with hierarchical RBAC or an external policy engine:

```java
@Service
public class HierarchicalAuthorizationManager implements AuthorizationManager {

    @Override
    public void checkRole(AuthenticatedUser user, String[] required) {
        Set<String> effective = expandRoles(user.getRoles());
        if (Arrays.stream(required).noneMatch(effective::contains)) {
            throw new SecurityAuthorizationException(
                user.getUsername(), required, user.getRoles(), AuthorizationType.ROLE);
        }
    }

    @Override
    public void checkPermission(AuthenticatedUser user, String[] permissions) {
        if (Arrays.stream(permissions).noneMatch(user.getPermissions()::contains)) {
            throw new SecurityAuthorizationException(
                user.getUsername(), permissions, user.getPermissions(), AuthorizationType.PERMISSION);
        }
    }

    private Set<String> expandRoles(Set<String> roles) {
        // e.g. ADMIN implies MANAGER implies USER
        Set<String> expanded = new HashSet<>(roles);
        if (roles.contains("ADMIN")) { expanded.add("MANAGER"); expanded.add("USER"); }
        if (roles.contains("MANAGER")) { expanded.add("USER"); }
        return expanded;
    }
}
```

---

## 5. Custom `AuthenticationAdapter`

Add support for a new authentication token type (e.g., API key, SAML, mTLS certificate):

```java
@Component
public class ApiKeyAuthenticationAdapter implements AuthenticationAdapter {

    @Override
    public boolean supports(Authentication authentication) {
        return authentication instanceof ApiKeyAuthenticationToken;
    }

    @Override
    public AuthenticatedUser convert(Authentication authentication) {
        ApiKeyAuthenticationToken token = (ApiKeyAuthenticationToken) authentication;
        ApiKeyDetails details = (ApiKeyDetails) token.getPrincipal();
        return AuthenticatedUser.builder(details.getKeyId())
                .userId(details.getOwnerId())
                .roles(details.getRoles())
                .permissions(details.getScopes())
                .build();
    }

    @Override
    public int getOrder() {
        return 20; // higher priority than the default JWT adapter (order=50)
    }
}
```

`SecurityContextFilter` automatically discovers all `AuthenticationAdapter` beans and selects the first one (by ascending order) that returns `supports(authentication) == true`.

---

## 6. Custom `PasswordEncoder`

```java
@Configuration
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new Argon2PasswordEncoder(16, 32, 1, 65536, 10);
    }
}
```

---

## 7. Custom `SecurityFilterChain`

Override the entire filter chain if you need full control (e.g., CORS, custom matchers, additional filters):

```java
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain myFilterChain(
            HttpSecurity http,
            JwtAuthenticationFilter jwtFilter,
            SecurityContextFilter contextFilter,
            AuthenticationEntryPoint entryPoint,
            AccessDeniedHandler accessDeniedHandler) throws Exception {

        http.csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .cors(cors -> cors.configurationSource(corsSource()))
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(entryPoint)
                .accessDeniedHandler(accessDeniedHandler))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**", "/actuator/health").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated())
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterAfter(contextFilter, JwtAuthenticationFilter.class);

        return http.build();
    }
}
```

---

## 8. Custom Error Responses

Override `AuthenticationEntryPoint` for 401 responses, or `AccessDeniedHandler` for 403 responses:

```java
@Component
public class MyAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException {
        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write("""
            { "code": "AUTH_REQUIRED", "path": "%s" }
            """.formatted(request.getRequestURI()));
    }
}
```
