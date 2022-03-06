package com.refreshtokenjwt.app.service;

import com.refreshtokenjwt.app.modal.RefreshToken;

import java.util.Optional;

public interface IRefreshTokenService {

    public Optional<RefreshToken> findByToken(String token);
    public RefreshToken createRefreshToken(int userId);
    public RefreshToken verifyExpiration(RefreshToken token);
    public int deleteByUserId(int userId);
}
