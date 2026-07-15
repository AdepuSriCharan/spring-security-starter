# Authorization

Spring Security Explainer provides three annotation-driven authorization mechanisms, all enforced by `AuthorizationAspect` via Spring AOP — no service-layer code required.

---

## How It Works

Authorization annotations are evaluated **after** the request has been authenticated and the `AuthenticatedUser` has been populated in `SecurityUserContext`. The `AuthorizationAspect` intercepts the annotated controller method before it executes and calls the appropriate `AuthorizationManager` method.

```mermaid
flowchart TD
    A[HTTP Request arrives] --> B[Filter chain authenticates]
    B --> C[SecurityContextFilter populates SecurityUserContext]
    C --> D[Controller method is called]
    D --> E{Authorization annotation present?}
    E -->|@RequireRole| F[AuthorizationAspect.checkRole]
    E -->|@RequirePermission| G[AuthorizationAspect.checkPermission]
    E -->|@RequireOwner| H[AuthorizationAspect.checkOwner]
    E -->|None| I[Business logic executes]
    F --> J[AuthorizationManager.checkRole]
    G --> K[AuthorizationManager.checkPermission]
    H --> L[SpEL evaluates expression against method args]
    J --> M{Has required role?}
    K --> N{Has required permission?}
    L --> O{userId == currentUser.userId?}
    M -->|Yes| I
    N -->|Yes| I
    O -->|Yes| I
    M -->|No| P[SecurityAuthorizationException ROLE]
    N -->|No| Q[SecurityAuthorizationException PERMISSION]
    O -->|No| R[SecurityAuthorizationException OWNERSHIP]
    P --> S[SecurityExceptionHandler → 403 JSON]
    Q --> S
    R --> S
```

---

## `@RequireRole`

Restricts a controller method to users who hold **at least one** of the specified roles.

```java
import com.sricharan.security.core.annotation.RequireRole;

// Single role
@GetMapping("/admin/dashboard")
@RequireRole("ADMIN")
public Dashboard getDashboard() { ... }

// Multiple roles — OR logic (any one is sufficient)
@GetMapping("/reports")
@RequireRole({"ADMIN", "MANAGER"})
public List<Report> getReports() { ... }
```

**Annotation definition:**
```java
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireRole {
    String[] value();
}
```

**Error response when denied:**
```json
{
  "error": "FORBIDDEN",
  "message": "Access denied for user 'john'. Required role: [ADMIN]. User has: [USER]",
  "type": "ROLE",
  "required": ["ADMIN"],
  "actual": ["USER"],
  "timestamp": "2026-01-15T10:30:00Z"
}
```

---

## `@RequirePermission`

Restricts a controller method to users who hold **at least one** of the specified permissions. Permissions are fine-grained strings, typically in `resource:action` format.

```java
import com.sricharan.security.core.annotation.RequirePermission;

// Single permission
@DeleteMapping("/posts/{id}")
@RequirePermission("post:delete")
public void deletePost(@PathVariable Long id) { ... }

// Multiple permissions — OR logic
@PutMapping("/settings")
@RequirePermission({"settings:write", "admin:all"})
public void updateSettings(@RequestBody SettingsRequest req) { ... }
```

**Error response when denied:**
```json
{
  "error": "FORBIDDEN",
  "message": "Access denied for user 'john'. Required permission: [post:delete]. User has: []",
  "type": "PERMISSION",
  "required": ["post:delete"],
  "actual": [],
  "timestamp": "2026-01-15T10:30:00Z"
}
```

---

## `@RequireOwner`

Restricts a controller method to the user who **owns** the resource identified by a SpEL expression. The evaluated result is compared against `AuthenticatedUser.getUserId()`.

```java
import com.sricharan.security.core.annotation.RequireOwner;

// Simple path variable
@GetMapping("/users/{userId}/profile")
@RequireOwner("#userId")
public UserProfile getProfile(@PathVariable String userId) { ... }

// Nested property from request body
@PutMapping("/orders/{orderId}")
@RequireOwner("#request.customerId")
public Order updateOrder(
        @PathVariable String orderId,
        @RequestBody UpdateOrderRequest request) { ... }
```

> **Note:** `@RequireOwner` works best when the resource owner ID is directly available as a method argument (e.g., a path variable). When the owner ID must be looked up from the database (e.g., by a post ID), enforce ownership in the service layer using `SecurityUserContext.requireCurrentUser()` instead.

**Error response when denied:**
```json
{
  "error": "FORBIDDEN",
  "message": "Access denied for user 'john'. Not the owner of resource 'admin-id'.",
  "type": "OWNERSHIP",
  "resourceId": "admin-id",
  "timestamp": "2026-01-15T10:30:00Z"
}
```

---

## Accessing the Current User

Use `SecurityUserContext` to access the authenticated user inside any service or component that runs on the request thread:

```java
@Service
public class PostService {

    public PostResponse createPost(CreatePostRequest request) {
        // Returns null if not authenticated
        AuthenticatedUser user = SecurityUserContext.getCurrentUser();

        // Throws IllegalStateException if not authenticated
        AuthenticatedUser user = SecurityUserContext.requireCurrentUser();

        String userId = user.getUserId();
        String username = user.getUsername();
        Set<String> roles = user.getRoles();
        Set<String> permissions = user.getPermissions();
        boolean isAdmin = user.hasRole("ADMIN");
        boolean canDelete = user.hasPermission("post:delete");

        // Access raw JWT claims (if populated by the adapter)
        String email = user.getAttribute("email");
    }
}
```

> **Warning:** `SecurityUserContext` uses a plain `ThreadLocal`. It is **not** propagated to `@Async` methods, `CompletableFuture` tasks, Kafka listeners, or WebFlux reactive pipelines. Capture the user before crossing a thread boundary.

---

## Combining Annotations

You can combine multiple annotations on the same method. All conditions must pass:

```java
@GetMapping("/users/{userId}/admin-data")
@RequireRole("ADMIN")          // must be an admin
@RequireOwner("#userId")       // AND must be accessing their own record
public AdminData getAdminData(@PathVariable String userId) { ... }
```

The AOP aspects evaluate in the order that Spring applies them. Both must pass for the method to execute.

---

## Customizing Authorization Logic

The default `DefaultAuthorizationManager` uses simple set-intersection (`anyMatch`). Replace it with your own implementation to support hierarchical roles, external policy engines (OPA, Casbin), or custom logic:

```java
@Service
public class HierarchicalAuthorizationManager implements AuthorizationManager {

    // SUPER_ADMIN implies ADMIN implies MANAGER implies USER
    private static final Map<String, Set<String>> HIERARCHY = Map.of(
        "SUPER_ADMIN", Set.of("SUPER_ADMIN", "ADMIN", "MANAGER", "USER"),
        "ADMIN",       Set.of("ADMIN", "MANAGER", "USER"),
        "MANAGER",     Set.of("MANAGER", "USER"),
        "USER",        Set.of("USER")
    );

    @Override
    public void checkRole(AuthenticatedUser user, String[] required) {
        Set<String> effective = user.getRoles().stream()
            .flatMap(r -> HIERARCHY.getOrDefault(r, Set.of(r)).stream())
            .collect(Collectors.toSet());

        boolean hasRole = Arrays.stream(required).anyMatch(effective::contains);
        if (!hasRole) {
            throw new SecurityAuthorizationException(
                user.getUsername(), required, user.getRoles(), AuthorizationType.ROLE);
        }
    }

    @Override
    public void checkPermission(AuthenticatedUser user, String[] permissions) {
        // same pattern
    }
}
```

Because `DefaultAuthorizationManager` is registered with `@ConditionalOnMissingBean`, declaring the above `@Service` is enough to replace it — no further configuration needed.

---

## Public Endpoints

Endpoints that should bypass authentication entirely are configured via:

```properties
security.public-endpoints=/register,/health,/actuator/**,/api/v1/public/**
```

In INTERNAL mode, `/login`, `/refresh`, and `/logout` are always public regardless of this property.
