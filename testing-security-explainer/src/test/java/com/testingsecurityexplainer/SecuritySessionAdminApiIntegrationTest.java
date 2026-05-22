package com.testingsecurityexplainer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class SecuritySessionAdminApiIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void listSessionsWithoutTokenReturnsUnauthorized() throws Exception {
        mockMvc.perform(get("/security/sessions").param("userId", "any-user"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void listSessionsWithNonAdminTokenReturnsForbidden() throws Exception {
        String username = unique("user");
        String password = "Pass@123";
        RegisterResult user = register("/register", username, password);
        TokenPair userTokens = login(username, password);

        mockMvc.perform(get("/security/sessions")
                        .param("userId", user.id())
                        .header("Authorization", "Bearer " + userTokens.accessToken()))
                .andExpect(status().isForbidden());
    }

    @Test
    void adminCanListRevokeSingleAndRevokeAllSessions() throws Exception {
        String userUsername = unique("user");
        String adminUsername = unique("admin");
        String password = "Pass@123";

        RegisterResult user = register("/register", userUsername, password);
        register("/register/admin", adminUsername, password);

        // Two logins for the same user create two refresh-backed sessions.
        login(userUsername, password);
        login(userUsername, password);
        TokenPair adminTokens = login(adminUsername, password);

        MvcResult listBefore = mockMvc.perform(get("/security/sessions")
                        .param("userId", user.id())
                        .header("Authorization", "Bearer " + adminTokens.accessToken()))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode beforeSessions = objectMapper.readTree(listBefore.getResponse().getContentAsString());
        assertThat(beforeSessions.isArray()).isTrue();
        assertThat(beforeSessions.size()).isGreaterThanOrEqualTo(2);

        String sessionIdToRevoke = beforeSessions.get(0).get("sessionId").asText();
        int beforeCount = beforeSessions.size();

        mockMvc.perform(delete("/security/sessions/{sessionId}", sessionIdToRevoke)
                        .param("userId", user.id())
                        .header("Authorization", "Bearer " + adminTokens.accessToken()))
                .andExpect(status().isOk());

        MvcResult listAfterSingleRevoke = mockMvc.perform(get("/security/sessions")
                        .param("userId", user.id())
                        .header("Authorization", "Bearer " + adminTokens.accessToken()))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode afterSingle = objectMapper.readTree(listAfterSingleRevoke.getResponse().getContentAsString());
        assertThat(afterSingle.size()).isEqualTo(beforeCount - 1);

        mockMvc.perform(delete("/security/sessions/user/{userId}", user.id())
                        .header("Authorization", "Bearer " + adminTokens.accessToken()))
                .andExpect(status().isOk());

        MvcResult listAfterAllRevoke = mockMvc.perform(get("/security/sessions")
                        .param("userId", user.id())
                        .header("Authorization", "Bearer " + adminTokens.accessToken()))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode afterAll = objectMapper.readTree(listAfterAllRevoke.getResponse().getContentAsString());
        assertThat(afterAll.size()).isZero();
    }

    private RegisterResult register(String endpoint, String username, String password) throws Exception {
        String requestBody = objectMapper.writeValueAsString(Map.of(
                "username", username,
                "password", password
        ));
        MvcResult result = mockMvc.perform(post(endpoint)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isCreated())
                .andReturn();

        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        return new RegisterResult(body.get("id").asText(), body.get("username").asText());
    }

    private TokenPair login(String username, String password) throws Exception {
        String requestBody = objectMapper.writeValueAsString(Map.of(
                "username", username,
                "password", password
        ));
        MvcResult result = mockMvc.perform(post("/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        return new TokenPair(body.get("accessToken").asText(), body.get("refreshToken").asText());
    }

    private String unique(String prefix) {
        return prefix + "_" + System.nanoTime();
    }

    private record RegisterResult(String id, String username) {}

    private record TokenPair(String accessToken, String refreshToken) {}
}
