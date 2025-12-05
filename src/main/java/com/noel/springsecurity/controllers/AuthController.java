package com.noel.springsecurity.controllers;

import com.noel.springsecurity.dto.request.*;
import com.noel.springsecurity.dto.response.ApiMessageResponse;
import com.noel.springsecurity.dto.response.AuthResponse;
import com.noel.springsecurity.dto.response.OtpResponse;
import com.noel.springsecurity.services.IAuthService;
import com.noel.springsecurity.utils.CookieUtil;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final IAuthService authService;
    private final CookieUtil cookieUtil;

    // Send OTP ---
    @PostMapping("/send-otp")
    public ResponseEntity<ApiMessageResponse> sendOtp(@Valid @RequestBody OtpRequest request) {
        authService.sendRegistrationOtp(request.email());
        return ResponseEntity.ok(new ApiMessageResponse(
                "OTP sent successfully. Please check your email."
        ));
    }

    // Verify OTP & Get preAuth-token ---
    @PostMapping("/verify-otp")
    public ResponseEntity<OtpResponse> verifyOtp(@Valid @RequestBody VerifyOtpRequest request) {
        String tempToken = authService.verifyOtp(request.email(), request.otp());
        return ResponseEntity.ok(new OtpResponse(tempToken));
    }

    // registration
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader,
            @Valid @RequestBody RegisterRequest request,
            UriComponentsBuilder uriBuilder
    ) {
        String preAuthToken = authHeader.startsWith("Bearer ")
                ? authHeader.substring(7)
                : authHeader;
        IAuthService.AuthResult result = authService.register(request, preAuthToken);
        var uri = uriBuilder.path("/api/v1/users/{id}")
                .buildAndExpand(result.user().id())
                .toUri();
        // Create HttpOnly Cookie for Refresh Token
        ResponseCookie cookie = cookieUtil.createRefreshTokenCookie(result.refreshToken());

        return ResponseEntity.created(uri)
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(new AuthResponse(result.accessToken(), result.user()));
    }

    // Login
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        IAuthService.AuthResult result = authService.login(request);

        ResponseCookie cookie = cookieUtil.createRefreshTokenCookie(result.refreshToken());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(new AuthResponse(result.accessToken(), result.user()));
    }

    // refresh Token
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@CookieValue(name = "refresh_token") String refreshToken) {
        IAuthService.AuthResult result = authService.refreshToken(refreshToken);
        ResponseCookie newCookie = cookieUtil.createRefreshTokenCookie(result.refreshToken());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, newCookie.toString())
                .body(new AuthResponse(result.accessToken(), result.user()));
    }

    // logout
    @PostMapping("/logout")
    public ResponseEntity<ApiMessageResponse> logout(@CookieValue(name = "refresh_token", required = false) String refreshToken) {
        if (refreshToken != null) {
            authService.logout(refreshToken);
        }
        ResponseCookie cleanCookie = cookieUtil.getCleanRefreshTokenCookie();
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cleanCookie.toString())
                .body(new ApiMessageResponse("Logged out successfully"));
    }

    // forgot password
    @PostMapping("/forgot-password")
    public ResponseEntity<ApiMessageResponse> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        authService.requestPasswordReset(request.email());
        return ResponseEntity.ok(new ApiMessageResponse(
                "If an account with that email exists, a password reset link has been sent."
        ));
    }

    // reset password
    @PostMapping("/reset-password")
    public ResponseEntity<ApiMessageResponse> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        authService.resetPassword(request.token(), request.newPassword());
        return ResponseEntity.ok(new ApiMessageResponse(
                "Password successfully updated. Please login with your new password."
        ));
    }
}