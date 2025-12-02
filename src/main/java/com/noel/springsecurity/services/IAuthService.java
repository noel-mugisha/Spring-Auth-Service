package com.noel.springsecurity.services;

import com.noel.springsecurity.dto.UserDto;
import com.noel.springsecurity.dto.request.LoginRequest;
import com.noel.springsecurity.dto.request.RegisterRequest;

public interface IAuthService {

    UserDto register(RegisterRequest request);

    void verifyEmail(String token);

    AuthResult login(LoginRequest request);

    AuthResult refreshToken(String incomingRefreshToken);

    void logout(String incomingRefreshToken);

    void requestPasswordReset(String email);

    void resetPassword(String token, String newPassword);


    /**
     * Internal DTO to carry tokens and user data from Service to Controller.
     */
    record AuthResult(String accessToken, String refreshToken, UserDto user) {}
}