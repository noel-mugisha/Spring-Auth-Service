package com.noel.springsecurity.services.impls;

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
import com.noel.springsecurity.services.IRefreshTokenService;
import com.noel.springsecurity.utils.TokenHashUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements IAuthService {
    private final IUserRepository userRepository;
    private final IEmailVerificationRepository emailVerificationRepository;
    private final IRefreshTokenService refreshTokenService;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final ApplicationEventPublisher eventPublisher;
    private final IUserMapper userMapper;
    @Value("${app.security.email.reset-password-expiration}")
    private int resetPasswordExpirationMinutes;
    @Value("${app.security.email.reset-password-url}")
    private String passwordResetLink;

    // SEND OTP
    @Override
    @Transactional
    public void sendRegistrationOtp(String email) {
        if (userRepository.existsByEmail(email)) {
            throw new UserAlreadyExistsException("Email already in use. Please login.");
        }
        // Generate Secure OTP
        String otp = String.format("%06d", new SecureRandom().nextInt(999999));
        // Save OTP in the database
        EmailVerification verification = new EmailVerification(
                email,
                otp,
                LocalDateTime.now().plusMinutes(10) // Valid for 10 mins
        );
        emailVerificationRepository.save(verification);

        // Publish Async Event (Sends Email)
        eventPublisher.publishEvent(new SendOtpEvent(email, otp));
    }

    // VERIFY OTP
    @Override
    @Transactional
    public String verifyOtp(String email, String otp) {
        EmailVerification verification = emailVerificationRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("Invalid email or OTP not found"));
        if (verification.getExpiryDate().isBefore(LocalDateTime.now())) {
            throw new LinkExpiredException("OTP has expired. Please request a new one.");
        }
        if (!verification.getOtpCode().equals(otp)) {
            throw new BadCredentialsException("Invalid OTP code.");
        }
        // Cleanup (One-time use)
        emailVerificationRepository.delete(verification);
        // Issue "Pre-Auth" Token
        return jwtService.generateRegistrationToken(email);
    }

    // REGISTER (Finalize)
    @Override
    @Transactional
    public AuthResult register(RegisterRequest request, String preAuthToken) {
        if (jwtService.isTokenExpired(preAuthToken) || !jwtService.isRegistrationToken(preAuthToken)) {
            throw new BadCredentialsException("Invalid or expired registration session.");
        }
        String email = jwtService.extractUserSubject(preAuthToken);
        if (userRepository.existsByEmail(email)) {
            throw new UserAlreadyExistsException("Email already in use.");
        }
        // Create User
        User user = new User();
        user.setFirstName(request.firstName());
        user.setLastName(request.lastName());
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setRole(ERole.USER);
        user.setEnabled(true);

        User savedUser = userRepository.save(user);
        String accessToken = jwtService.generateAccessToken(savedUser);
        String refreshToken = refreshTokenService.createRefreshToken(savedUser);

        return new AuthResult(accessToken, refreshToken, userMapper.toDto(savedUser));
    }

    // STANDARD LOGIN
    @Override
    @Transactional
    public AuthResult login(LoginRequest request) {
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.email(), request.password())
            );
        } catch (BadCredentialsException e) {
            throw new BadCredentialsException("Invalid email or password");
        } catch (DisabledException e) {
            throw new DisabledException("Account is disabled.");
        }
        UserPrincipal principal = (UserPrincipal) authentication.getPrincipal();
        User user = principal.getUser();
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = refreshTokenService.createRefreshToken(user);

        return new AuthResult(accessToken, refreshToken, userMapper.toDto(user));
    }

    // REFRESH TOKEN
    @Override
    @Transactional
    public AuthResult refreshToken(String incomingRefreshToken) {
        RefreshToken existingToken = refreshTokenService.findByToken(incomingRefreshToken)
                .orElseThrow(() -> new TokenRefreshException("Invalid refresh token"));
        refreshTokenService.verifyExpiration(existingToken);
        User user = existingToken.getUser();
        if (!user.isEnabled()) {
            throw new TokenRefreshException("User account is disabled");
        }
        // Rotate Token - delete old, create new
        refreshTokenService.delete(existingToken);
        String newAccessToken = jwtService.generateAccessToken(user);
        String newRefreshToken = refreshTokenService.createRefreshToken(user);

        return new AuthResult(newAccessToken, newRefreshToken, userMapper.toDto(user));
    }

    // LOGOUT
    @Override
    @Transactional
    public void logout(String incomingRefreshToken) {
        if (incomingRefreshToken == null) return;
        refreshTokenService.deleteByToken(incomingRefreshToken);
        SecurityContextHolder.clearContext();
    }

    // PASSWORD RESET REQUEST
    @Override
    @Transactional
    public void requestPasswordReset(String email) {
        userRepository.findByEmail(email).ifPresent(user -> {
            String rawToken = UUID.randomUUID().toString();
            String hashedToken = TokenHashUtil.hashToken(rawToken);
            user.setPasswordResetToken(hashedToken);
            user.setPasswordResetTokenExpiry(
                    LocalDateTime.now().plusMinutes(resetPasswordExpirationMinutes)
            );
            userRepository.save(user);

            String fullName = user.getFirstName() + " " + user.getLastName();
            String link = passwordResetLink + "?token=" + rawToken;
            // Publish Async Event
            eventPublisher.publishEvent(new PasswordResetEvent(user.getEmail(), fullName, link));
        });
    }

    // RESET PASSWORD
    @Override
    @Transactional
    public void resetPassword(String token, String newPassword) {
        String hashedToken = TokenHashUtil.hashToken(token);
        User user = userRepository.findByPasswordResetToken(hashedToken)
                .orElseThrow(() -> new ResourceNotFoundException("Invalid or expired password reset token"));
        if (user.getPasswordResetTokenExpiry().isBefore(LocalDateTime.now())) {
            throw new LinkExpiredException("Password reset link has expired");
        }
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setPasswordResetToken(null);
        user.setPasswordResetTokenExpiry(null);
        userRepository.save(user);
        // Security: Revoke all sessions to force re-login with a new password
        refreshTokenService.deleteByUser(user);
    }
}