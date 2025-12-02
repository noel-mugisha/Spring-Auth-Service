package com.noel.springsecurity.controllers;

import com.noel.springsecurity.dto.request.ForgotPasswordRequest;
import com.noel.springsecurity.dto.request.LoginRequest;
import com.noel.springsecurity.dto.request.RegisterRequest;
import com.noel.springsecurity.dto.request.ResetPasswordRequest;
import com.noel.springsecurity.dto.response.ApiMessageResponse;
import com.noel.springsecurity.dto.response.AuthResponse;
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

    @PostMapping("/register")
    public ResponseEntity<ApiMessageResponse> register(
            @Valid @RequestBody RegisterRequest request,
            UriComponentsBuilder uriBuilder
    ) {
        var userDto = authService.register(request);
        var uri = uriBuilder.path("/api/v1/users/{id}").buildAndExpand(userDto.id()).toUri();
        return ResponseEntity.created(uri).body(new ApiMessageResponse(
                "User registered successfully. Please check your email to verify your account."
        ));
    }

    @PostMapping("/verify-email")
    public ResponseEntity<ApiMessageResponse> verifyEmail(@RequestParam("token") String token) {
        authService.verifyEmail(token);
        return ResponseEntity.ok(new ApiMessageResponse(
                "Email verified successfully. You can now login."
        ));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        IAuthService.AuthResult result = authService.login(request);
        // Create HttpOnly Cookie for Refresh Token
        ResponseCookie cookie = cookieUtil.createRefreshTokenCookie(result.refreshToken());
        // Return Access Token in Body, Refresh Token in Cookie
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(new AuthResponse(result.accessToken(), result.user()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@CookieValue(name = "refresh_token") String refreshToken) {
        IAuthService.AuthResult result = authService.refreshToken(refreshToken);
        // Rotate: Set new Cookie
        ResponseCookie newCookie = cookieUtil.createRefreshTokenCookie(result.refreshToken());
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, newCookie.toString())
                .body(new AuthResponse(result.accessToken(), result.user()));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiMessageResponse> logout(@CookieValue(name = "refresh_token", required = false) String refreshToken) {
        if (refreshToken != null) {
            authService.logout(refreshToken);
        }
        // Clear the cookie
        ResponseCookie cleanCookie = cookieUtil.getCleanRefreshTokenCookie();
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cleanCookie.toString())
                .body(
                        new ApiMessageResponse("Logged out successfully")
                );
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<ApiMessageResponse> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        authService.requestPasswordReset(request.email());
        return ResponseEntity.ok(new ApiMessageResponse("If an account with that email exists, a password reset link has been sent."));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<ApiMessageResponse> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        authService.resetPassword(request.token(), request.newPassword());
        return ResponseEntity.ok(new ApiMessageResponse("Password successfully updated. Please login with your new password."));
    }
}