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
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import java.util.concurrent.atomic.AtomicReference;

@SpringBootTest
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class UserMockTests {

    MockMvc mockMvc;

    static AtomicReference<JWTResponse> jwtToken = new AtomicReference<JWTResponse>();

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
        signupRequest.setUsername("User2");
        signupRequest.setEmail("user2_userrole@user.com");
        signupRequest.setPassword("user2");


        mockMvc.perform( MockMvcRequestBuilders
                .post("/api/auth/signup")
                .content(asJsonString(signupRequest))
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(MockMvcResultMatchers.status().isOk());
    }

    @Test
    @Order(2)
    public void loginUserReturnStatus200() throws Exception {

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername("User2");
        loginRequest.setPassword("user2");

        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders
                .post("/api/auth/signin")
                .content(asJsonString(loginRequest))
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andReturn();

        String responseBody = mvcResult.getResponse().getContentAsString();
        JWTResponse jwtResponse = new Gson().fromJson(responseBody, JWTResponse.class);


        UserMockTests.jwtToken.set(jwtResponse);

    }

    @Test
    @Order(3)
    public void refreshTokenReturnStatus200() throws Exception{

        Thread.sleep(1000 * 10);

        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.post("/api/auth/refreshtoken")
                .content(asJsonString(new TokenRefreshRequest(UserMockTests.jwtToken.get().getRefreshToken())))
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andReturn();

        String responseBody = mvcResult.getResponse().getContentAsString();
        TokenRefreshResponse tokenRefreshResponse = new Gson().fromJson(responseBody, TokenRefreshResponse.class);

        UserMockTests.jwtToken.get().setToken(tokenRefreshResponse.getAccessToken());
    }

    @Test
    @Order(4)
    public void openUserPage() throws Exception {

        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.get("/api/pages/user")
                .header("Authorization", "Bearer " + UserMockTests.jwtToken.get().getToken())
                .contentType(MediaType.APPLICATION_JSON)
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
                .header("Authorization", "Bearer " + UserMockTests.jwtToken.get().getToken())
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.message").value("Log out successful!"))
                .andReturn();
    }
}
