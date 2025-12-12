package com.noel.springsecurity.services;

import com.noel.springsecurity.entities.RefreshToken;
import com.noel.springsecurity.entities.User;

import java.util.Optional;

public interface IRefreshTokenService {

    String createRefreshToken(User user);

    Optional<RefreshToken> findByToken(String rawToken);

    RefreshToken verifyExpiration(RefreshToken token);

    void deleteByToken(String rawToken);

    void delete(RefreshToken token);

    void deleteByUser(User user);
}