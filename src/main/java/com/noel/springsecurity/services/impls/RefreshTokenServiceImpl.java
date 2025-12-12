package com.noel.springsecurity.services.impls;

import com.noel.springsecurity.entities.RefreshToken;
import com.noel.springsecurity.entities.User;
import com.noel.springsecurity.exceptions.TokenRefreshException;
import com.noel.springsecurity.repositories.IRefreshTokenRepository;
import com.noel.springsecurity.security.jwt.JwtService;
import com.noel.springsecurity.services.IRefreshTokenService;
import com.noel.springsecurity.utils.TokenHashUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements IRefreshTokenService {

    private final IRefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;

    @Value("${app.security.jwt.refresh-token-expiration}")
    private long refreshTokenDurationMs;

    @Override
    @Transactional
    public String createRefreshToken(User user) {
        String rawToken = jwtService.generateRefreshToken();
        String hashedToken = TokenHashUtil.hashToken(rawToken);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setTokenHash(hashedToken);
        refreshToken.setExpiresAt(LocalDateTime.now().plusNanos(refreshTokenDurationMs * 1000000));

        refreshTokenRepository.save(refreshToken);

        return rawToken;
    }

    @Override
    public Optional<RefreshToken> findByToken(String rawToken) {
        String tokenHash = TokenHashUtil.hashToken(rawToken);
        return refreshTokenRepository.findByTokenHash(tokenHash);
    }

    @Override
    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.isRevoked()) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException("Refresh token expired. Please login again.");
        }
        return token;
    }

    @Override
    @Transactional
    public void deleteByToken(String rawToken) {
        String tokenHash = TokenHashUtil.hashToken(rawToken);
        refreshTokenRepository.deleteByTokenHash(tokenHash);
    }

    @Override
    public void delete(RefreshToken token) {
        refreshTokenRepository.delete(token);
    }

    @Override
    @Transactional
    public void deleteByUser(User user) {
        refreshTokenRepository.deleteByUser(user);
    }
}