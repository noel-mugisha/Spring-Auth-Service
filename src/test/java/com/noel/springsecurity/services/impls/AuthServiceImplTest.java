package com.noel.springsecurity.services.impls;

import com.noel.springsecurity.dto.UserDto;
import com.noel.springsecurity.dto.request.LoginRequest;
import com.noel.springsecurity.dto.request.RegisterRequest;
import com.noel.springsecurity.entities.EmailVerification;
import com.noel.springsecurity.entities.RefreshToken;
import com.noel.springsecurity.entities.User;
import com.noel.springsecurity.enums.ERole;
import com.noel.springsecurity.events.PasswordResetEvent;
import com.noel.springsecurity.events.SendOtpEvent;
import com.noel.springsecurity.exceptions.LinkExpiredException;
import com.noel.springsecurity.exceptions.ResourceNotFoundException;
import com.noel.springsecurity.exceptions.TokenRefreshException;
import com.noel.springsecurity.exceptions.UserAlreadyExistsException;
import com.noel.springsecurity.mappers.IUserMapper;
import com.noel.springsecurity.repositories.IEmailVerificationRepository;
import com.noel.springsecurity.repositories.IUserRepository;
import com.noel.springsecurity.security.UserPrincipal;
import com.noel.springsecurity.security.jwt.JwtService;
import com.noel.springsecurity.services.IAuthService;
import com.noel.springsecurity.services.IMfaService;
import com.noel.springsecurity.services.IRefreshTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    @Mock private IUserRepository userRepository;
    @Mock private IEmailVerificationRepository emailVerificationRepository;
    @Mock private IRefreshTokenService refreshTokenService;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private JwtService jwtService;
    @Mock private AuthenticationManager authenticationManager;
    @Mock private ApplicationEventPublisher eventPublisher;
    @Mock private IUserMapper userMapper;
    @Mock private IMfaService mfaService;

    private AuthServiceImpl authService;
    private User user;

    @BeforeEach
    void setUp() {
        authService = new AuthServiceImpl(
                userRepository, emailVerificationRepository, refreshTokenService,
                passwordEncoder, jwtService, authenticationManager, eventPublisher,
                userMapper, mfaService
        );
        ReflectionTestUtils.setField(authService, "resetPasswordExpirationMinutes", 15);
        ReflectionTestUtils.setField(authService, "passwordResetLink", "https://app.example.com/reset-password");

        user = new User();
        user.setId(UUID.randomUUID());
        user.setEmail("jane@example.com");
        user.setRole(ERole.USER);
        user.setMfaEnabled(false);
    }

    // ===================== sendRegistrationOtp =====================

    @Test
    void sendRegistrationOtp_savesAndEmailsAFreshSixDigitCode() {
        when(userRepository.existsByEmail("jane@example.com")).thenReturn(false);

        authService.sendRegistrationOtp("jane@example.com");

        ArgumentCaptor<EmailVerification> savedCaptor = ArgumentCaptor.forClass(EmailVerification.class);
        verify(emailVerificationRepository).save(savedCaptor.capture());
        EmailVerification saved = savedCaptor.getValue();

        assertThat(saved.getEmail()).isEqualTo("jane@example.com");
        assertThat(saved.getOtpCode()).matches("\\d{6}");
        assertThat(saved.getExpiryDate()).isAfter(LocalDateTime.now());

        ArgumentCaptor<SendOtpEvent> eventCaptor = ArgumentCaptor.forClass(SendOtpEvent.class);
        verify(eventPublisher).publishEvent(eventCaptor.capture());
        // The event must carry the exact same code that was persisted, not a second random one.
        assertThat(eventCaptor.getValue().otpCode()).isEqualTo(saved.getOtpCode());
    }

    @Test
    void sendRegistrationOtp_rejectsAnEmailThatIsAlreadyRegistered() {
        when(userRepository.existsByEmail("jane@example.com")).thenReturn(true);

        assertThatThrownBy(() -> authService.sendRegistrationOtp("jane@example.com"))
                .isInstanceOf(UserAlreadyExistsException.class);

        verifyNoInteractions(emailVerificationRepository, eventPublisher);
    }

    // ===================== verifyOtp =====================

    @Test
    void verifyOtp_issuesAPreAuthTokenAndConsumesTheOtpOnSuccess() {
        EmailVerification verification = new EmailVerification(
                "jane@example.com", "482913", LocalDateTime.now().plusMinutes(5));
        when(emailVerificationRepository.findByEmail("jane@example.com"))
                .thenReturn(Optional.of(verification));
        when(jwtService.generateRegistrationToken("jane@example.com")).thenReturn("pre-auth-token");

        String result = authService.verifyOtp("jane@example.com", "482913");

        assertThat(result).isEqualTo("pre-auth-token");
        verify(emailVerificationRepository).delete(verification); // one-time use
    }

    @Test
    void verifyOtp_throwsWhenNoOtpWasEverRequested() {
        when(emailVerificationRepository.findByEmail("jane@example.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.verifyOtp("jane@example.com", "482913"))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    void verifyOtp_throwsWhenTheCodeHasExpired() {
        EmailVerification verification = new EmailVerification(
                "jane@example.com", "482913", LocalDateTime.now().minusMinutes(1));
        when(emailVerificationRepository.findByEmail("jane@example.com"))
                .thenReturn(Optional.of(verification));

        assertThatThrownBy(() -> authService.verifyOtp("jane@example.com", "482913"))
                .isInstanceOf(LinkExpiredException.class);
    }

    @Test
    void verifyOtp_rejectsAWrongCodeWithoutConsumingIt() {
        EmailVerification verification = new EmailVerification(
                "jane@example.com", "482913", LocalDateTime.now().plusMinutes(5));
        when(emailVerificationRepository.findByEmail("jane@example.com"))
                .thenReturn(Optional.of(verification));

        assertThatThrownBy(() -> authService.verifyOtp("jane@example.com", "000000"))
                .isInstanceOf(BadCredentialsException.class);

        // A typo shouldn't burn the person's only valid code — they should be able to retry.
        verify(emailVerificationRepository, never()).delete(any());
    }

    // ===================== register =====================

    @Test
    void register_createsTheAccountAndIssuesTokens() {
        when(jwtService.isTokenExpired("pre-auth-token")).thenReturn(false);
        when(jwtService.isRegistrationToken("pre-auth-token")).thenReturn(true);
        when(jwtService.extractUserSubject("pre-auth-token")).thenReturn("jane@example.com");
        when(userRepository.existsByEmail("jane@example.com")).thenReturn(false);
        when(passwordEncoder.encode("Str0ng!Pass")).thenReturn("encoded-password");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(jwtService.generateAccessToken(any())).thenReturn("access-token");
        when(refreshTokenService.createRefreshToken(any())).thenReturn("refresh-token");
        when(userMapper.toDto(any())).thenReturn(
                new UserDto(UUID.randomUUID(), "Jane", "Doe", "jane@example.com", "USER", false));

        IAuthService.AuthResult result = authService.register(
                new RegisterRequest("Jane", "Doe", "Str0ng!Pass"), "pre-auth-token");

        assertThat(result.accessToken()).isEqualTo("access-token");
        ArgumentCaptor<User> savedCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(savedCaptor.capture());
        assertThat(savedCaptor.getValue().getPassword()).isEqualTo("encoded-password");
        assertThat(savedCaptor.getValue().getRole()).isEqualTo(ERole.USER);
        assertThat(savedCaptor.getValue().isEnabled()).isTrue();
    }

    @Test
    void register_rejectsAnExpiredOrWrongScopePreAuthToken() {
        when(jwtService.isTokenExpired("bad-token")).thenReturn(true);

        assertThatThrownBy(() -> authService.register(
                new RegisterRequest("Jane", "Doe", "Str0ng!Pass"), "bad-token"))
                .isInstanceOf(BadCredentialsException.class);

        verifyNoInteractions(userRepository);
    }

    @Test
    void register_rejectsIfTheEmailGotTakenAfterTheOtpStepFinished() {
        when(jwtService.isTokenExpired("pre-auth-token")).thenReturn(false);
        when(jwtService.isRegistrationToken("pre-auth-token")).thenReturn(true);
        when(jwtService.extractUserSubject("pre-auth-token")).thenReturn("jane@example.com");
        when(userRepository.existsByEmail("jane@example.com")).thenReturn(true);

        assertThatThrownBy(() -> authService.register(
                new RegisterRequest("Jane", "Doe", "Str0ng!Pass"), "pre-auth-token"))
                .isInstanceOf(UserAlreadyExistsException.class);
    }

    // ===================== login =====================

    private void mockSuccessfulPasswordCheck() {
        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(new UserPrincipal(user));
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
    }

    @Test
    void login_issuesTokensImmediatelyWhenMfaIsOff() {
        mockSuccessfulPasswordCheck();
        when(jwtService.generateAccessToken(user)).thenReturn("access-token");
        when(refreshTokenService.createRefreshToken(user)).thenReturn("refresh-token");
        when(userMapper.toDto(user)).thenReturn(
                new UserDto(user.getId(), "Jane", "Doe", user.getEmail(), "USER", false));

        IAuthService.LoginResult result = authService.login(new LoginRequest("jane@example.com", "pw"));

        assertThat(result).isInstanceOf(IAuthService.LoginResult.Success.class);
        IAuthService.AuthResult authResult = ((IAuthService.LoginResult.Success) result).result();
        assertThat(authResult.accessToken()).isEqualTo("access-token");
        verify(jwtService, never()).generateMfaChallengeToken(any());
    }

    @Test
    void login_returnsAChallengeInsteadOfTokensWhenMfaIsOn() {
        user.setMfaEnabled(true);
        mockSuccessfulPasswordCheck();
        when(jwtService.generateMfaChallengeToken(user.getId())).thenReturn("mfa-challenge-token");

        IAuthService.LoginResult result = authService.login(new LoginRequest("jane@example.com", "pw"));

        assertThat(result).isInstanceOf(IAuthService.LoginResult.MfaRequired.class);
        assertThat(((IAuthService.LoginResult.MfaRequired) result).mfaToken())
                .isEqualTo("mfa-challenge-token");
        verify(jwtService, never()).generateAccessToken(any());
        verify(refreshTokenService, never()).createRefreshToken(any());
    }

    // ===================== verifyMfaAndLogin =====================

    @Test
    void verifyMfaAndLogin_rejectsAnExpiredChallengeToken() {
        when(jwtService.isTokenExpired("bad-token")).thenReturn(true);

        assertThatThrownBy(() -> authService.verifyMfaAndLogin("bad-token", "123456"))
                .isInstanceOf(BadCredentialsException.class);

        verifyNoInteractions(userRepository);
    }

    @Test
    void verifyMfaAndLogin_rejectsATokenOfTheWrongScope() {
        when(jwtService.isTokenExpired("some-token")).thenReturn(false);
        when(jwtService.isMfaChallengeToken("some-token")).thenReturn(false);

        assertThatThrownBy(() -> authService.verifyMfaAndLogin("some-token", "123456"))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    void verifyMfaAndLogin_failsClosedIfMfaWasDisabledAfterTheChallengeWasIssued() {
        user.setMfaEnabled(false);
        when(jwtService.isTokenExpired("mfa-token")).thenReturn(false);
        when(jwtService.isMfaChallengeToken("mfa-token")).thenReturn(true);
        when(jwtService.extractUserSubject("mfa-token")).thenReturn(user.getId().toString());
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.verifyMfaAndLogin("mfa-token", "123456"))
                .isInstanceOf(BadCredentialsException.class);

        verifyNoInteractions(mfaService);
    }

    @Test
    void verifyMfaAndLogin_throwsIfTheUserNoLongerExists() {
        UUID missingId = UUID.randomUUID();
        when(jwtService.isTokenExpired("mfa-token")).thenReturn(false);
        when(jwtService.isMfaChallengeToken("mfa-token")).thenReturn(true);
        when(jwtService.extractUserSubject("mfa-token")).thenReturn(missingId.toString());
        when(userRepository.findById(missingId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.verifyMfaAndLogin("mfa-token", "123456"))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    void verifyMfaAndLogin_issuesTokensOnAValidTotpCode() {
        user.setMfaEnabled(true);
        user.setMfaSecret("SECRET123");
        when(jwtService.isTokenExpired("mfa-token")).thenReturn(false);
        when(jwtService.isMfaChallengeToken("mfa-token")).thenReturn(true);
        when(jwtService.extractUserSubject("mfa-token")).thenReturn(user.getId().toString());
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(mfaService.isValidTotpCode("SECRET123", "654321")).thenReturn(true);
        when(jwtService.generateAccessToken(user)).thenReturn("access-token");
        when(refreshTokenService.createRefreshToken(user)).thenReturn("refresh-token");
        when(userMapper.toDto(user)).thenReturn(
                new UserDto(user.getId(), "Jane", "Doe", user.getEmail(), "USER", true));

        IAuthService.AuthResult result = authService.verifyMfaAndLogin("mfa-token", "654321");

        assertThat(result.accessToken()).isEqualTo("access-token");
        verify(mfaService, never()).redeemRecoveryCode(any(), any());
    }

    @Test
    void verifyMfaAndLogin_fallsBackToARecoveryCodeWhenTheTotpCodeIsWrong() {
        user.setMfaEnabled(true);
        user.setMfaSecret("SECRET123");
        when(jwtService.isTokenExpired("mfa-token")).thenReturn(false);
        when(jwtService.isMfaChallengeToken("mfa-token")).thenReturn(true);
        when(jwtService.extractUserSubject("mfa-token")).thenReturn(user.getId().toString());
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(mfaService.isValidTotpCode("SECRET123", "aaaa-bbbb")).thenReturn(false);
        when(mfaService.redeemRecoveryCode(user, "aaaa-bbbb")).thenReturn(true);
        when(jwtService.generateAccessToken(user)).thenReturn("access-token");
        when(refreshTokenService.createRefreshToken(user)).thenReturn("refresh-token");
        when(userMapper.toDto(user)).thenReturn(
                new UserDto(user.getId(), "Jane", "Doe", user.getEmail(), "USER", true));

        IAuthService.AuthResult result = authService.verifyMfaAndLogin("mfa-token", "aaaa-bbbb");

        assertThat(result.accessToken()).isEqualTo("access-token");
    }

    @Test
    void verifyMfaAndLogin_rejectsLoginWhenNeitherCheckPasses() {
        user.setMfaEnabled(true);
        user.setMfaSecret("SECRET123");
        when(jwtService.isTokenExpired("mfa-token")).thenReturn(false);
        when(jwtService.isMfaChallengeToken("mfa-token")).thenReturn(true);
        when(jwtService.extractUserSubject("mfa-token")).thenReturn(user.getId().toString());
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(mfaService.isValidTotpCode("SECRET123", "000000")).thenReturn(false);
        when(mfaService.redeemRecoveryCode(user, "000000")).thenReturn(false);

        assertThatThrownBy(() -> authService.verifyMfaAndLogin("mfa-token", "000000"))
                .isInstanceOf(BadCredentialsException.class);

        verify(jwtService, never()).generateAccessToken(any());
    }

    // ===================== refreshToken =====================

    @Test
    void refreshToken_rotatesTheTokenPairOnSuccess() {
        RefreshToken existingToken = new RefreshToken();
        existingToken.setUser(user);
        user.setEnabled(true);
        when(refreshTokenService.findByToken("old-refresh")).thenReturn(Optional.of(existingToken));
        when(refreshTokenService.verifyExpiration(existingToken)).thenReturn(existingToken);
        when(jwtService.generateAccessToken(user)).thenReturn("new-access");
        when(refreshTokenService.createRefreshToken(user)).thenReturn("new-refresh");
        when(userMapper.toDto(user)).thenReturn(
                new UserDto(user.getId(), "Jane", "Doe", user.getEmail(), "USER", false));

        IAuthService.AuthResult result = authService.refreshToken("old-refresh");

        assertThat(result.accessToken()).isEqualTo("new-access");
        verify(refreshTokenService).delete(existingToken); // old token is retired, never reusable
    }

    @Test
    void refreshToken_rejectsATokenThatDoesNotExist() {
        when(refreshTokenService.findByToken("ghost-token")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.refreshToken("ghost-token"))
                .isInstanceOf(TokenRefreshException.class);
    }

    @Test
    void refreshToken_rejectsADisabledAccountEvenWithAValidToken() {
        RefreshToken existingToken = new RefreshToken();
        user.setEnabled(false);
        existingToken.setUser(user);
        when(refreshTokenService.findByToken("old-refresh")).thenReturn(Optional.of(existingToken));
        when(refreshTokenService.verifyExpiration(existingToken)).thenReturn(existingToken);

        assertThatThrownBy(() -> authService.refreshToken("old-refresh"))
                .isInstanceOf(TokenRefreshException.class);
    }

    // ===================== logout =====================

    @Test
    void logout_revokesTheSessionWhenARefreshTokenIsPresent() {
        authService.logout("some-refresh-token");

        verify(refreshTokenService).deleteByToken("some-refresh-token");
    }

    @Test
    void logout_doesNothingWhenNoRefreshTokenWasPresent() {
        authService.logout(null);

        verifyNoInteractions(refreshTokenService);
    }

    // ===================== requestPasswordReset =====================

    @Test
    void requestPasswordReset_setsATokenAndPublishesAnEmailEventWhenTheAccountExists() {
        when(userRepository.findByEmail("jane@example.com")).thenReturn(Optional.of(user));

        authService.requestPasswordReset("jane@example.com");

        ArgumentCaptor<User> savedCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(savedCaptor.capture());
        assertThat(savedCaptor.getValue().getPasswordResetToken()).isNotBlank();
        assertThat(savedCaptor.getValue().getPasswordResetTokenExpiry()).isAfter(LocalDateTime.now());

        ArgumentCaptor<PasswordResetEvent> eventCaptor = ArgumentCaptor.forClass(PasswordResetEvent.class);
        verify(eventPublisher).publishEvent(eventCaptor.capture());
        assertThat(eventCaptor.getValue().resetLink()).startsWith("https://app.example.com/reset-password?token=");
    }

    @Test
    void requestPasswordReset_staysSilentForAnUnknownEmail() {
        // Security property: never reveal whether an email is registered.
        when(userRepository.findByEmail("ghost@example.com")).thenReturn(Optional.empty());

        authService.requestPasswordReset("ghost@example.com");

        verify(userRepository, never()).save(any());
        verifyNoInteractions(eventPublisher);
    }

    // ===================== resetPassword =====================

    @Test
    void resetPassword_updatesThePasswordAndRevokesAllExistingSessions() {
        user.setPasswordResetToken("hashed-token");
        user.setPasswordResetTokenExpiry(LocalDateTime.now().plusMinutes(5));
        when(userRepository.findByPasswordResetToken(any())).thenReturn(Optional.of(user));
        when(passwordEncoder.encode("NewStr0ng!Pass")).thenReturn("new-encoded-password");

        authService.resetPassword("raw-token", "NewStr0ng!Pass");

        assertThat(user.getPassword()).isEqualTo("new-encoded-password");
        assertThat(user.getPasswordResetToken()).isNull();
        assertThat(user.getPasswordResetTokenExpiry()).isNull();
        verify(refreshTokenService).deleteByUser(user); // forces re-login everywhere
    }

    @Test
    void resetPassword_rejectsAnUnknownToken() {
        when(userRepository.findByPasswordResetToken(any())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.resetPassword("raw-token", "NewStr0ng!Pass"))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    void resetPassword_rejectsAnExpiredTokenWithoutTouchingThePassword() {
        user.setPasswordResetTokenExpiry(LocalDateTime.now().minusMinutes(1));
        when(userRepository.findByPasswordResetToken(any())).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.resetPassword("raw-token", "NewStr0ng!Pass"))
                .isInstanceOf(LinkExpiredException.class);

        verifyNoInteractions(passwordEncoder);
    }
}