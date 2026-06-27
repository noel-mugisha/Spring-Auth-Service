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

    // Standard Login (may require a follow-up MFA step)
    LoginResult login(LoginRequest request);

    // Complete login after the MFA challenge has been verified
    AuthResult verifyMfaAndLogin(String mfaToken, String code);

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

    /**
     * Outcome of a login attempt: either it succeeded outright, or an MFA
     * code is still required before tokens are issued.
     */
    sealed interface LoginResult {
        record Success(AuthResult result) implements LoginResult {}
        record MfaRequired(String mfaToken) implements LoginResult {}
    }
}