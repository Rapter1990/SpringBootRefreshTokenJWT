package com.refreshtokenjwt.app.service.impl;

import com.refreshtokenjwt.app.exception.RefreshTokenException;
import com.refreshtokenjwt.app.modal.RefreshToken;
import com.refreshtokenjwt.app.modal.User;
import com.refreshtokenjwt.app.repository.RefreshTokenRepository;
import com.refreshtokenjwt.app.service.IRefreshTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@Transactional
public class RefreshTokenService implements IRefreshTokenService {

    @Value("${jwt.secret.refrEshexpireMs}")
    private Long refreshTokenDurationMs;

    RefreshTokenRepository refreshTokenRepository;

    UserService userService;

    @Autowired
    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository,UserService userService) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userService = userService;
    }

    @Override
    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    @Override
    public RefreshToken createRefreshToken(int userId) {

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(userService.findById(userId));
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        refreshToken.setToken(UUID.randomUUID().toString());

        return refreshTokenRepository.save(refreshToken);
    }

    @Override
    public RefreshToken verifyExpiration(RefreshToken token) {

        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
        }

        return token;
    }

    @Override
    public int deleteByUserId(int userId) {

        User user = userService.findById(userId);
        return refreshTokenRepository.deleteByUser(user);
    }
}
