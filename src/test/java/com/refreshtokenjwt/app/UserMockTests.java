package com.refreshtokenjwt.app;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.refreshtokenjwt.app.payload.request.LoginRequest;
import com.refreshtokenjwt.app.payload.request.LogoutRequest;
import com.refreshtokenjwt.app.payload.request.SignupRequest;
import com.refreshtokenjwt.app.payload.request.TokenRefreshRequest;
import com.refreshtokenjwt.app.payload.response.JWTResponse;
import com.refreshtokenjwt.app.payload.response.TokenRefreshResponse;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.junit.jupiter.api.Order;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;

@SpringBootTest
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@DirtiesContext
@ActiveProfiles("test")
public class UserMockTests {

    private final MockMvc mockMvc;

    private static String token;
    private static String refreshToken;
    // it seems accessToken and token is the same, so use a one of the names
    private static String accessToken;

    @Autowired
    public UserMockTests(MockMvc mockMvc) {
        this.mockMvc = mockMvc;
    }

    public static String asJsonString(final Object obj) {
        try {
            return new ObjectMapper().writeValueAsString(obj);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @Order(1)
    public void registerUserReturnStatus200() throws Exception {

        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setUsername("User7");
        signupRequest.setEmail("user7_userrole@user.com");
        signupRequest.setPassword("user7");


        mockMvc.perform(MockMvcRequestBuilders
                        .post("/api/auth/signup")
                        .content(asJsonString(signupRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.message").value("User registered successfully!"));
    }

    @Test
    @Order(2)
    public void loginUserReturnStatus200() throws Exception {

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername("User7");
        loginRequest.setPassword("user7");

        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders
                        .post("/api/auth/signin")
                        .content(asJsonString(loginRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andReturn();

        String responseBody = mvcResult.getResponse().getContentAsString();
        JWTResponse jwtResponse = new Gson().fromJson(responseBody, JWTResponse.class);


        token = jwtResponse.getToken();
        refreshToken = jwtResponse.getRefreshToken();

    }

    @Test
    @Order(3)
    public void refreshTokenReturnStatus200() throws Exception {

        Thread.sleep(1000 * 60);

        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.post("/api/auth/refreshtoken")
                        .content(asJsonString(new TokenRefreshRequest(refreshToken)))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andReturn();

        String responseBody = mvcResult.getResponse().getContentAsString();
        TokenRefreshResponse tokenRefreshResponse = new Gson().fromJson(responseBody, TokenRefreshResponse.class);

        token = tokenRefreshResponse.getAccessToken();
    }

    @Test
    @Order(4)
    public void openUserPage() throws Exception {

        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.get("/api/pages/user")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + token)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andReturn();

        String responseBody = mvcResult.getResponse().getContentAsString();
        Assertions.assertThat(responseBody).isEqualTo("User Content.");
    }

    @Test
    @Order(5)
    public void logoutUserReturnStatus200() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.post("/api/auth/logout")
                        .content(asJsonString(new LogoutRequest(6)))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(MockMvcResultMatchers.status().isOk())
                // I don't know why you should provide this message, check AuthController line 189
                .andExpect(MockMvcResultMatchers.jsonPath("$.message").value("Log out successful!"))
                .andReturn();
    }
}
