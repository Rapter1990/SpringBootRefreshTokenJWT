package com.refreshtokenjwt.app.payload.request;

import lombok.AllArgsConstructor;
import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
@AllArgsConstructor
public class TokenRefreshRequest {

    @NotBlank
    private String refreshToken;

}