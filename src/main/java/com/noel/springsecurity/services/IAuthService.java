package com.noel.springsecurity.services;

import com.noel.springsecurity.dto.UserDto;
import com.noel.springsecurity.dto.request.LoginRequest;
import com.noel.springsecurity.dto.request.RegisterRequest;

public interface IAuthService {

    // Send OTP
    void sendRegistrationOtp(String email);

    // Verify OTP and get Pre-Auth Token
    String verifyOtp(String email, String otp);

    // Complete Registration using Pre-Auth Token
    AuthResult register(RegisterRequest request, String preAuthToken);

    // Standard Login
    AuthResult login(LoginRequest request);

    // Token Management
    AuthResult refreshToken(String incomingRefreshToken);
    void logout(String incomingRefreshToken);

    // Password Reset
    void requestPasswordReset(String email);
    void resetPassword(String token, String newPassword);

    /**
     * Data Carrier for Login/Register success
     */
    record AuthResult(String accessToken, String refreshToken, UserDto user) {}
}