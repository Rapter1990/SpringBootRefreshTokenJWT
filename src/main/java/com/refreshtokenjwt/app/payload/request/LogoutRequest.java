package com.refreshtokenjwt.app.payload.request;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class LogoutRequest {

    private int userId;
}
