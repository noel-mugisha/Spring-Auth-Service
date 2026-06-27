package com.noel.springsecurity.controllers;

import com.noel.springsecurity.dto.UserDto;
import com.noel.springsecurity.dto.request.*;
import com.noel.springsecurity.dto.response.ApiMessageResponse;
import com.noel.springsecurity.dto.response.AuthResponse;
import com.noel.springsecurity.dto.response.MfaChallengeResponse;
import com.noel.springsecurity.services.IAuthService;
import com.noel.springsecurity.utils.CookieUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock private IAuthService authService;
    @Mock private CookieUtil cookieUtil;

    private AuthController authController;

    @BeforeEach
    void setUp() {
        authController = new AuthController(authService, cookieUtil);
    }

    private void mockCookie() {
        when(cookieUtil.createRefreshTokenCookie(anyString()))
                .thenReturn(ResponseCookie.from("refresh_token", "value").httpOnly(true).build());
    }

    private void mockCleanCookie() {
        when(cookieUtil.getCleanRefreshTokenCookie())
                .thenReturn(ResponseCookie.from("refresh_token", "").maxAge(0).build());
    }

    @Test
    void register_returns201WithLocationAndSetsTheRefreshCookie() {
        mockCookie();
        UUID newUserId = UUID.randomUUID();
        UserDto userDto = new UserDto(newUserId, "Jane", "Doe", "jane@example.com", "USER", false);
        IAuthService.AuthResult authResult = new IAuthService.AuthResult("access-token", "refresh-token", userDto);
        when(authService.register(any(), org.mockito.ArgumentMatchers.eq("pre-auth-token")))
                .thenReturn(authResult);

        ResponseEntity<AuthResponse> response = authController.register(
                "Bearer pre-auth-token",
                new RegisterRequest("Jane", "Doe", "Str0ng!Pass"),
                UriComponentsBuilder.newInstance()
        );

        assertThat(response.getStatusCode().value()).isEqualTo(201);
        assertThat(response.getHeaders().getLocation().toString()).contains(newUserId.toString());
        assertThat(response.getHeaders().get(HttpHeaders.SET_COOKIE)).isNotNull();
        assertThat(response.getBody().accessToken()).isEqualTo("access-token");
    }

    @Test
    void register_stripsTheBearerPrefixBeforePassingTheTokenToTheService() {
        mockCookie();
        UserDto userDto = new UserDto(UUID.randomUUID(), "Jane", "Doe", "jane@example.com", "USER", false);
        when(authService.register(any(), anyString()))
                .thenReturn(new IAuthService.AuthResult("a", "r", userDto));

        authController.register("Bearer raw-token-value",
                new RegisterRequest("Jane", "Doe", "Str0ng!Pass"), UriComponentsBuilder.newInstance());

        ArgumentCaptor<String> tokenCaptor = ArgumentCaptor.forClass(String.class);
        verify(authService).register(any(), tokenCaptor.capture());
        assertThat(tokenCaptor.getValue()).isEqualTo("raw-token-value");
    }

    @Test
    void register_acceptsARawTokenWithNoBearerPrefix() {
        mockCookie();
        UserDto userDto = new UserDto(UUID.randomUUID(), "Jane", "Doe", "jane@example.com", "USER", false);
        when(authService.register(any(), anyString()))
                .thenReturn(new IAuthService.AuthResult("a", "r", userDto));

        authController.register("raw-token-value",
                new RegisterRequest("Jane", "Doe", "Str0ng!Pass"), UriComponentsBuilder.newInstance());

        ArgumentCaptor<String> tokenCaptor = ArgumentCaptor.forClass(String.class);
        verify(authService).register(any(), tokenCaptor.capture());
        assertThat(tokenCaptor.getValue()).isEqualTo("raw-token-value");
    }

    @Test
    void login_returnsTokensAndSetsACookieOnSuccess() {
        mockCookie();
        UserDto userDto = new UserDto(UUID.randomUUID(), "Jane", "Doe", "jane@example.com", "USER", false);
        IAuthService.AuthResult authResult = new IAuthService.AuthResult("access-token", "refresh-token", userDto);
        when(authService.login(any())).thenReturn(new IAuthService.LoginResult.Success(authResult));

        ResponseEntity<?> response = authController.login(new LoginRequest("jane@example.com", "pw"));

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).isInstanceOf(AuthResponse.class);
        assertThat(((AuthResponse) response.getBody()).accessToken()).isEqualTo("access-token");
        assertThat(response.getHeaders().get(HttpHeaders.SET_COOKIE)).isNotNull();
    }

    @Test
    void login_returnsAChallengeWithNoCookieWhenMfaIsRequired() {
        when(authService.login(any()))
                .thenReturn(new IAuthService.LoginResult.MfaRequired("mfa-challenge-token"));

        ResponseEntity<?> response = authController.login(new LoginRequest("jane@example.com", "pw"));

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        MfaChallengeResponse body = (MfaChallengeResponse) response.getBody();
        assertThat(body.mfaRequired()).isTrue();
        assertThat(body.mfaToken()).isEqualTo("mfa-challenge-token");
        // Crucial: no session should start until the second factor is verified
        assertThat(response.getHeaders().get(HttpHeaders.SET_COOKIE)).isNull();
    }

    @Test
    void verifyMfaLogin_returnsTokensAndSetsACookieOnSuccess() {
        mockCookie();
        UserDto userDto = new UserDto(UUID.randomUUID(), "Jane", "Doe", "jane@example.com", "USER", true);
        IAuthService.AuthResult authResult = new IAuthService.AuthResult("access-token", "refresh-token", userDto);
        when(authService.verifyMfaAndLogin("mfa-token", "654321")).thenReturn(authResult);

        ResponseEntity<AuthResponse> response =
                authController.verifyMfaLogin(new MfaLoginVerifyRequest("mfa-token", "654321"));

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody().accessToken()).isEqualTo("access-token");
        assertThat(response.getHeaders().get(HttpHeaders.SET_COOKIE)).isNotNull();
    }

    @Test
    void refresh_rotatesTheCookieOnSuccess() {
        mockCookie();
        UserDto userDto = new UserDto(UUID.randomUUID(), "Jane", "Doe", "jane@example.com", "USER", false);
        when(authService.refreshToken("old-refresh"))
                .thenReturn(new IAuthService.AuthResult("new-access", "new-refresh", userDto));

        ResponseEntity<AuthResponse> response = authController.refresh("old-refresh");

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody().accessToken()).isEqualTo("new-access");
        assertThat(response.getHeaders().get(HttpHeaders.SET_COOKIE)).isNotNull();
    }

    @Test
    void logout_revokesTheSessionWhenARefreshTokenIsPresent() {
        mockCleanCookie();

        ResponseEntity<ApiMessageResponse> response = authController.logout("token-abc");

        verify(authService).logout("token-abc");
        assertThat(response.getStatusCode().value()).isEqualTo(200);
    }

    @Test
    void logout_stillClearsTheCookieWhenNoRefreshTokenWasPresent() {
        mockCleanCookie();

        ResponseEntity<ApiMessageResponse> response = authController.logout(null);

        verify(authService, org.mockito.Mockito.never()).logout(any());
        assertThat(response.getHeaders().get(HttpHeaders.SET_COOKIE)).isNotNull();
        assertThat(response.getBody().message()).isEqualTo("Logged out successfully");
    }

    @Test
    void forgotPassword_alwaysDelegatesAndReturnsTheGenericMessage() {
        ResponseEntity<ApiMessageResponse> response =
                authController.forgotPassword(new ForgotPasswordRequest("jane@example.com"));

        verify(authService).requestPasswordReset("jane@example.com");
        assertThat(response.getBody().message()).contains("password reset link");
    }

    @Test
    void resetPassword_delegatesToTheServiceAndConfirms() {
        ResponseEntity<ApiMessageResponse> response =
                authController.resetPassword(new ResetPasswordRequest("raw-token", "NewStr0ng!Pass"));

        verify(authService).resetPassword("raw-token", "NewStr0ng!Pass");
        assertThat(response.getBody().message()).contains("updated");
    }
}