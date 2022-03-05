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

    AtomicReference<String> token = new AtomicReference<String>();
    AtomicReference<String> refreshToken = new AtomicReference<String>();
    AtomicReference<String> accessToken = new AtomicReference<String>();

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


        mockMvc.perform( MockMvcRequestBuilders
                .post("/api/auth/signup")
                .content(asJsonString(signupRequest))
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.id").exists());
    }

    @Test
    @Order(2)
    public void loginUserReturnStatus200() throws Exception {

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername("User7");
        loginRequest.setPassword("user7");

        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders
                .post("/api/auth/signin")
                .header("Authorization", "Bearer " + token)
                .content(asJsonString(loginRequest))
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andReturn();

        String responseBody = mvcResult.getResponse().getContentAsString();
        JWTResponse jwtResponse = new Gson().fromJson(responseBody, JWTResponse.class);


        token.set(jwtResponse.getToken());
        refreshToken.set(jwtResponse.getRefreshToken());

    }

    @Test
    @Order(3)
    public void refreshTokenReturnStatus200() throws Exception{

        Thread.sleep(1000 * 60);

        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.post("/api/auth/refreshtoken")
                .content(asJsonString(new TokenRefreshRequest(refreshToken.get())))
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andReturn();

        String responseBody = mvcResult.getResponse().getContentAsString();
        TokenRefreshResponse tokenRefreshResponse = new Gson().fromJson(responseBody, TokenRefreshResponse.class);

        accessToken.set(tokenRefreshResponse.getAccessToken());
    }

    @Test
    @Order(4)
    public void openUserPage() throws Exception {

        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.get("/api/pages/user")
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
        mockMvc.perform(MockMvcRequestBuilders.post("/logout")
                .content(asJsonString(new LogoutRequest(6)))
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.message").value("Log out successful!"))
                .andReturn();
    }
}
