package com.sricharan.security.test;

import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests proving the authorization framework works end-to-end.
 *
 * <p>These tests verify:
 * <ul>
 *   <li>Unauthenticated access is blocked (401)</li>
 *   <li>Insufficient roles produce 403 with structured JSON</li>
 *   <li>Correct roles pass through</li>
 *   <li>Multi-role OR logic works</li>
 *   <li>Permission-based authorization works</li>
 * </ul>
 */
@SpringBootTest(classes = {TestApplication.class, TestSecurityConfig.class, DemoController.class})
@AutoConfigureMockMvc
class AuthorizationIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    // ── Public endpoint ─────────────────────────────────────

    @Test
    @DisplayName("Public endpoint is accessible without authentication")
    void publicEndpoint_noAuth_returns200() throws Exception {
        mockMvc.perform(get("/public"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.secured").value(false));
    }

    // ── Role-based authorization ────────────────────────────

    @Nested
    @DisplayName("@RequireRole tests")
    class RequireRoleTests {

        @Test
        @DisplayName("Unauthenticated user gets 401 on protected endpoint")
        void adminEndpoint_noAuth_returns401() throws Exception {
            mockMvc.perform(get("/admin"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("USER role cannot access ADMIN endpoint → 403 with JSON body")
        @WithMockUser(username = "user", roles = {"USER"})
        void adminEndpoint_userRole_returns403() throws Exception {
            mockMvc.perform(get("/admin"))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.error").value("FORBIDDEN"))
                    .andExpect(jsonPath("$.type").value("ROLE"))
                    .andExpect(jsonPath("$.required").isArray())
                    .andExpect(jsonPath("$.actual").isArray());
        }

        @Test
        @DisplayName("ADMIN role can access ADMIN endpoint → 200")
        @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
        void adminEndpoint_adminRole_returns200() throws Exception {
            mockMvc.perform(get("/admin"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Welcome to the admin area"))
                    .andExpect(jsonPath("$.user").value("admin"));
        }

        @Test
        @DisplayName("USER role can access USER endpoint → 200")
        @WithMockUser(username = "user", roles = {"USER"})
        void userEndpoint_userRole_returns200() throws Exception {
            mockMvc.perform(get("/user"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("User profile area"))
                    .andExpect(jsonPath("$.user").value("user"));
        }

        @Test
        @DisplayName("Multi-role OR logic: ADMIN can access ADMIN|MANAGER endpoint")
        @WithMockUser(username = "admin", roles = {"ADMIN"})
        void multiRoleEndpoint_adminRole_returns200() throws Exception {
            mockMvc.perform(get("/multi-role"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Accessible by ADMIN or MANAGER"));
        }

        @Test
        @DisplayName("Multi-role OR logic: USER cannot access ADMIN|MANAGER endpoint")
        @WithMockUser(username = "user", roles = {"USER"})
        void multiRoleEndpoint_userRole_returns403() throws Exception {
            mockMvc.perform(get("/multi-role"))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.error").value("FORBIDDEN"));
        }
    }

    // ── Permission-based authorization ──────────────────────

    @Nested
    @DisplayName("@RequirePermission tests")
    class RequirePermissionTests {

        @Test
        @DisplayName("User without required permission gets 403")
        @WithMockUser(username = "user", roles = {"USER"})
        void permissionEndpoint_noPermission_returns403() throws Exception {
            mockMvc.perform(get("/with-permission"))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.error").value("FORBIDDEN"))
                    .andExpect(jsonPath("$.type").value("PERMISSION"));
        }
    }

    // ── Ownership-based authorization ───────────────────────

    @Nested
    @DisplayName("@RequireOwner tests")
    class RequireOwnerTests {

        @Test
        @DisplayName("User accessing their own resource gets 200")
        @WithMockUser(username = "john", roles = {"USER"}) // SpringSecurityAuthenticationAdapter defaults userId to username
        void userProfileEndpoint_isOwner_returns200() throws Exception {
            mockMvc.perform(get("/users/john/profile"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("This is the user's private profile"))
                    .andExpect(jsonPath("$.user").value("john"))
                    .andExpect(jsonPath("$.userId").value("john"));
        }

        @Test
        @DisplayName("User accessing someone else's resource gets 403 with resourceId")
        @WithMockUser(username = "john", roles = {"USER"})
        void userProfileEndpoint_notOwner_returns403() throws Exception {
            mockMvc.perform(get("/users/admin/profile"))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.error").value("FORBIDDEN"))
                    .andExpect(jsonPath("$.type").value("OWNERSHIP"))
                    .andExpect(jsonPath("$.resourceId").value("admin"))
                    .andExpect(jsonPath("$.message").value("Access denied for user 'john'. Not the owner of resource 'admin'."));
        }
    }

    // ── Built-in Authentication / JWT tests ─────────────────

    @Nested
    @DisplayName("JWT Authentication Tests")
    class JwtAuthenticationTests {

        @Test
        @DisplayName("Valid login returns JWT token")
        void login_validCredentials_returnsToken() throws Exception {
            String loginJson = """
                    {
                        "username": "john",
                        "password": "password"
                    }
                    """;

            mockMvc.perform(post("/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(loginJson))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accessToken").exists())
                    .andExpect(jsonPath("$.accessToken").isString())
                    .andExpect(jsonPath("$.refreshToken").exists())
                    .andExpect(jsonPath("$.refreshToken").isString())
                    .andExpect(jsonPath("$.expiresIn").isNumber())
                    .andExpect(jsonPath("$.tokenType").value("Bearer"));
        }

        @Test
        @DisplayName("Invalid login returns 401")
        void login_invalidCredentials_returns401() throws Exception {
            String loginJson = """
                    {
                        "username": "john",
                        "password": "wrong-password"
                    }
                    """;

            mockMvc.perform(post("/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(loginJson))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error").value("UNAUTHORIZED"))
                    .andExpect(jsonPath("$.message").value("Invalid username or password."));
        }

        @Test
        @DisplayName("Accessing protected endpoint with valid JWT succeeds")
        void accessingEndpoint_withJwt_succeeds() throws Exception {
            // 1. Get Token
            String loginJson = """
                    {
                        "username": "admin",
                        "password": "admin"
                    }
                    """;

            String response = mockMvc.perform(post("/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(loginJson))
                    .andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString();

            String token = JsonPath.read(response, "$.accessToken");

            // 2. Use Token to access admin endpoint
            mockMvc.perform(get("/admin")
                            .header("Authorization", "Bearer " + token))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Welcome to the admin area"))
                    .andExpect(jsonPath("$.user").value("admin"));
            
            // 3. User Token to access ownership endpoint (extracts ID correctly)
            mockMvc.perform(get("/users/admin-id/profile")
                            .header("Authorization", "Bearer " + token))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("This is the user's private profile"))
                    .andExpect(jsonPath("$.user").value("admin"))
                    .andExpect(jsonPath("$.userId").value("admin-id"));
        }

        @Test
        @DisplayName("Refresh token returns new access + refresh token pair")
        void refreshEndpoint_withValidRefreshToken_succeeds() throws Exception {
            // 1. Login to get tokens
            String loginJson = """
                    {
                        "username": "admin",
                        "password": "admin"
                    }
                    """;

            String loginResponse = mockMvc.perform(post("/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(loginJson))
                    .andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString();

            String refreshToken = JsonPath.read(loginResponse, "$.refreshToken");

            // 2. Use refresh token to get new tokens
            String refreshJson = String.format("""
                    { "refreshToken": "%s" }
                    """, refreshToken);

            mockMvc.perform(post("/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(refreshJson))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accessToken").exists())
                    .andExpect(jsonPath("$.refreshToken").exists())
                    .andExpect(jsonPath("$.tokenType").value("Bearer"));
        }

        @Test
        @DisplayName("Refresh token rotation: old token is rejected after use")
        void refreshEndpoint_oldTokenRejectedAfterRotation() throws Exception {
            // 1. Login
            String loginJson = """
                    { "username": "admin", "password": "admin" }
                    """;

            String loginResponse = mockMvc.perform(post("/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(loginJson))
                    .andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString();

            String refreshToken = JsonPath.read(loginResponse, "$.refreshToken");

            // 2. Use refresh token (rotates it)
            String refreshJson = String.format("""
                    { "refreshToken": "%s" }
                    """, refreshToken);

            mockMvc.perform(post("/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(refreshJson))
                    .andExpect(status().isOk());

            // 3. Reuse the SAME old token → should be rejected (replay detection)
            mockMvc.perform(post("/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(refreshJson))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error").value("UNAUTHORIZED"));
        }

        @Test
        @DisplayName("Logout revokes refresh token")
        void logoutEndpoint_revokesToken() throws Exception {
            // 1. Login
            String loginJson = """
                    { "username": "john", "password": "password" }
                    """;

            String loginResponse = mockMvc.perform(post("/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(loginJson))
                    .andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString();

            String refreshToken = JsonPath.read(loginResponse, "$.refreshToken");

            // 2. Logout
            String logoutJson = String.format("""
                    { "refreshToken": "%s" }
                    """, refreshToken);

            mockMvc.perform(post("/logout")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(logoutJson))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Logged out successfully."));

            // 3. Try to use revoked token → should be rejected
            String refreshJson = String.format("""
                    { "refreshToken": "%s" }
                    """, refreshToken);

            mockMvc.perform(post("/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(refreshJson))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Unauthenticated request returns structured JSON 401")
        void unauthenticatedRequest_returnsJsonError() throws Exception {
            mockMvc.perform(get("/admin"))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error").value("UNAUTHORIZED"))
                    .andExpect(jsonPath("$.message").exists())
                    .andExpect(jsonPath("$.timestamp").exists());
        }
    }
}
