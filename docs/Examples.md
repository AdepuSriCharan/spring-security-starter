# Examples

Real-world integration examples showing how to use Spring Security Explainer in different scenarios.

---

## Example 1: Minimal INTERNAL Mode Setup

The smallest possible integration — an in-memory user for demonstration.

**`pom.xml`**
```xml
<dependency>
    <groupId>io.github.adepusricharan</groupId>
    <artifactId>security-starter</artifactId>
    <version>1.2.1</version>
</dependency>
```

**`application.properties`**
```properties
security.auth-mode=INTERNAL
security.jwt.secret=K8q+mNpWxZvJ7LcRhDfGnQeB5tA3ysYiU2oP6wMXkT0=
security.public-endpoints=/api/v1/public
```

**`SecurityConfig.java`**
```java
@Configuration
public class SecurityConfig {

    @Bean
    public UserAccountProvider userAccountProvider(PasswordEncoder encoder) {
        // In-memory users for demonstration
        record InMemUser(String id, String username, String password,
                         Set<String> roles, Set<String> permissions)
                implements UserAccount {}

        Map<String, UserAccount> users = Map.of(
            "alice", new InMemUser("1", "alice", encoder.encode("p@ssw0rd"),
                    Set.of("USER"), Set.of("post:read")),
            "admin", new InMemUser("2", "admin", encoder.encode("admin123"),
                    Set.of("ADMIN", "USER"), Set.of("post:read", "post:delete"))
        );

        return username -> Optional.ofNullable(users.get(username));
    }
}
```

**`PostController.java`**
```java
@RestController
@RequestMapping("/api/v1")
public class PostController {

    @GetMapping("/public")
    public Map<String, String> publicEndpoint() {
        return Map.of("status", "public");
    }

    @GetMapping("/posts")
    @RequireRole("USER")
    public List<String> listPosts() {
        AuthenticatedUser user = SecurityUserContext.requireCurrentUser();
        return List.of("Post 1 for " + user.getUsername(), "Post 2");
    }

    @DeleteMapping("/posts/{id}")
    @RequirePermission("post:delete")
    public ResponseEntity<Void> deletePost(@PathVariable Long id) {
        return ResponseEntity.noContent().build();
    }
}
```

**Try it:**
```bash
# Login
curl -s -X POST http://localhost:8080/login \
     -H 'Content-Type: application/json' \
     -d '{"username":"alice","password":"p@ssw0rd"}' | jq .

# Use the token
curl -s http://localhost:8080/api/v1/posts \
     -H 'Authorization: Bearer <accessToken>' | jq .
```

---

## Example 2: JPA + PostgreSQL Integration

The reference demo application (`testing-security-explainer`) demonstrates a full JPA integration.

**`UserService.java`** — implements `UserAccountProvider`:
```java
@Service
public class UserService implements UserAccountProvider {

    private final UserRepository userRepository;

    @Override
    public Optional<UserAccount> findByUsername(String username) {
        return userRepository.findByUsername(username).map(user -> user);
        // User entity implements UserAccount directly
    }
}
```

**`User.java`** — JPA entity implementing `UserAccount`:
```java
@Entity
@Table(name = "users")
public class User implements UserAccount {

    @Id
    private String id = UUID.randomUUID().toString();

    private String username;
    private String passwordHash;

    @ManyToMany(fetch = FetchType.EAGER)
    private Set<Role> roles;

    @ElementCollection
    private Set<String> permissions;

    @Override public String getId() { return id; }
    @Override public String getUsername() { return username; }
    @Override public String getPassword() { return passwordHash; }
    @Override public Set<String> getRoles() {
        return roles.stream().map(r -> r.getName().name()).collect(Collectors.toSet());
    }
    @Override public Set<String> getPermissions() { return permissions; }
}
```

---

## Example 3: Resource Ownership

Protecting a resource so only its owner can access it.

```java
@RestController
@RequestMapping("/api/v1/users")
public class UserProfileController {

    private final ProfileService profileService;

    // Only the user themselves can view their profile
    @GetMapping("/{userId}/profile")
    @RequireOwner("#userId")       // SpEL: evaluates #userId against AuthenticatedUser.getUserId()
    public UserProfile getProfile(@PathVariable String userId) {
        return profileService.getProfile(userId);
    }

    // The SpEL can also access nested properties
    @PutMapping("/{userId}/settings")
    @RequireOwner("#userId")
    public void updateSettings(
            @PathVariable String userId,
            @RequestBody UserSettings settings) {
        profileService.updateSettings(userId, settings);
    }
}
```

**Service-layer ownership (when owner ID requires a DB lookup):**
```java
@Service
public class PostService {

    @Transactional
    public Post updatePost(Long id, UpdatePostRequest request) {
        AuthenticatedUser currentUser = SecurityUserContext.requireCurrentUser();
        Post post = postRepository.findById(id)
            .orElseThrow(() -> new PostNotFoundException(id));

        // Manual ownership check when the owner ID is in the database
        if (!post.getAuthorId().equals(currentUser.getUserId())) {
            throw new SecurityAuthorizationException(
                currentUser.getUsername(),
                new String[]{post.getAuthorId()},
                Set.of(currentUser.getUserId()),
                SecurityAuthorizationException.AuthorizationType.OWNERSHIP,
                String.valueOf(id)
            );
        }

        post.setContent(request.getContent());
        return postRepository.save(post);
    }
}
```

---

## Example 4: Redis-Backed Refresh Tokens

For production deployments where horizontal scaling is required.

**`application.properties`**
```properties
security.auth-mode=INTERNAL
security.jwt.secret=${JWT_SECRET}
security.refresh.store-mode=REDIS
security.refresh.redis.key-prefix=myapp:auth:refresh
spring.data.redis.host=${REDIS_HOST}
spring.data.redis.port=6379
```

**`docker-compose.yml`** (for local development):
```yaml
services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  app:
    build: .
    ports:
      - "8080:8080"
    environment:
      JWT_SECRET: K8q+mNpWxZvJ7LcRhDfGnQeB5tA3ysYiU2oP6wMXkT0=
      REDIS_HOST: redis
    depends_on:
      - redis
```

---

## Example 5: Keycloak Integration

```properties
security.auth-mode=KEYCLOAK
spring.security.oauth2.resourceserver.jwt.issuer-uri=http://localhost:9090/realms/my-realm
security.keycloak.client-id=my-spring-app
```

Keycloak `realm_access.roles` → `AuthenticatedUser.getRoles()`.
Keycloak `resource_access.my-spring-app.roles` → `AuthenticatedUser.getPermissions()`.

```java
@GetMapping("/admin/dashboard")
@RequireRole("ADMIN")   // matches Keycloak realm-level role
public Dashboard getDashboard() { ... }

@DeleteMapping("/data/{id}")
@RequirePermission("data-admin")  // matches Keycloak client-level role
public void deleteData(@PathVariable Long id) { ... }
```

---

## Example 6: Custom Kafka Audit Sink

Route all security events to a Kafka topic:

```java
@Service
@RequiredArgsConstructor
public class KafkaSecurityAuditSink implements SecurityAuditSink {

    private final KafkaTemplate<String, SecurityAuditEvent> kafkaTemplate;

    private static final String TOPIC = "security-audit-events";

    @Override
    public void publish(SecurityAuditEvent event) {
        kafkaTemplate.send(TOPIC, event.getType().name(), event)
            .exceptionally(ex -> {
                // Log and continue — never let audit sink failure affect the request
                log.error("Failed to publish security event to Kafka", ex);
                return null;
            });
    }
}
```

No additional configuration needed — declaring this `@Service` replaces the default `JsonSecurityAuditSink` via `@ConditionalOnMissingBean`.

---

## Example 7: Testing Security-Protected Endpoints

```java
@SpringBootTest
@AutoConfigureMockMvc
class PostControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("USER can list posts")
    @WithMockUser(username = "alice", roles = {"USER"})
    void listPosts_withUserRole_returns200() throws Exception {
        mockMvc.perform(get("/api/v1/posts"))
               .andExpect(status().isOk());
    }

    @Test
    @DisplayName("USER cannot delete posts — needs post:delete permission")
    @WithMockUser(username = "alice", roles = {"USER"})
    void deletePost_withoutPermission_returns403() throws Exception {
        mockMvc.perform(delete("/api/v1/posts/1"))
               .andExpect(status().isForbidden())
               .andExpect(jsonPath("$.type").value("PERMISSION"));
    }

    @Test
    @DisplayName("Full flow: login → access protected endpoint")
    void loginAndAccessProtectedEndpoint() throws Exception {
        // 1. Login
        String response = mockMvc.perform(post("/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"username":"alice","password":"p@ssw0rd"}"""))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

        String token = JsonPath.read(response, "$.accessToken");

        // 2. Access protected endpoint
        mockMvc.perform(get("/api/v1/posts")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isOk());
    }
}
```

---

## Example 8: Using `SecurityUserContext` in a Service

```java
@Service
public class AuditableOrderService {

    private final OrderRepository orderRepository;

    public Order placeOrder(PlaceOrderRequest request) {
        // Get the authenticated user — always available on the request thread
        AuthenticatedUser user = SecurityUserContext.requireCurrentUser();

        Order order = Order.builder()
            .customerId(user.getUserId())
            .createdByUsername(user.getUsername())
            .items(request.getItems())
            .build();

        // No need to pass userId from the controller — the security context provides it
        return orderRepository.save(order);
    }
}
```
