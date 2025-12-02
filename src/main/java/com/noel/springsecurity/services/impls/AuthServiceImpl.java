package com.noel.springsecurity.services.impls;

import com.noel.springsecurity.dto.UserDto;
import com.noel.springsecurity.dto.request.LoginRequest;
import com.noel.springsecurity.dto.request.RegisterRequest;
import com.noel.springsecurity.entities.RefreshToken;
import com.noel.springsecurity.entities.User;
import com.noel.springsecurity.enums.ERole;
import com.noel.springsecurity.events.PasswordResetRequestedEvent;
import com.noel.springsecurity.events.RegistrationCompleteEvent;
import com.noel.springsecurity.exceptions.ResourceNotFoundException;
import com.noel.springsecurity.exceptions.TokenRefreshException;
import com.noel.springsecurity.exceptions.UserAlreadyExistsException;
import com.noel.springsecurity.exceptions.LinkExpiredException;
import com.noel.springsecurity.mappers.IUserMapper;
import com.noel.springsecurity.repositories.IRefreshTokenRepository;
import com.noel.springsecurity.repositories.IUserRepository;
import com.noel.springsecurity.security.UserPrincipal;
import com.noel.springsecurity.security.jwt.JwtService;
import com.noel.springsecurity.services.IAuthService;
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

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements IAuthService {
    private final IUserRepository userRepository;
    private final IRefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final ApplicationEventPublisher eventPublisher;
    private final IUserMapper userMapper;
    @Value("${app.security.jwt.refresh-token-expiration}")
    private long refreshTokenDurationMs;
    @Value("${app.security.email.reset-password-expiration}")
    private int resetPasswordExpirationMinutes;

    @Override
    @Transactional
    public UserDto register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new UserAlreadyExistsException("Email already in use");
        }

        User user = new User();
        user.setFullName(request.fullName());
        user.setEmail(request.email());
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setRole(ERole.USER);
        user.setEnabled(false); // Must verify email first
        user.setVerificationToken(UUID.randomUUID().toString());
        user.setVerificationTokenExpiry(LocalDateTime.now().plusHours(24));

        var savedUser = userRepository.save(user);

        // Publish event to send email async
        eventPublisher.publishEvent(new RegistrationCompleteEvent(user));
        return userMapper.toDto(savedUser);
    }

    @Override
    @Transactional
    public void verifyEmail(String token) {
        User user = userRepository.findByVerificationToken(token)
                .orElseThrow(() -> new ResourceNotFoundException("Invalid verification token"));

        if (user.getVerificationTokenExpiry().isBefore(LocalDateTime.now())) {
            throw new LinkExpiredException("Verification link has expired");
        }

        user.setEnabled(true);
        user.setVerificationToken(null);
        user.setVerificationTokenExpiry(null);
        userRepository.save(user);
    }

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
            throw new DisabledException("Account is disabled. Please verify your email.");
        }

        UserPrincipal principal = (UserPrincipal) authentication.getPrincipal();
        User user = principal.getUser();

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = createRefreshToken(user);

        return new AuthResult(accessToken, refreshToken, userMapper.toDto(user));
    }

    @Override
    @Transactional
    public AuthResult refreshToken(String incomingRefreshToken) {
        String tokenHash = TokenHashUtil.hashToken(incomingRefreshToken);
        RefreshToken existingToken = refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new TokenRefreshException("Invalid refresh token"));
        if (existingToken.isRevoked()) {
            refreshTokenRepository.delete(existingToken);
            throw new TokenRefreshException("Refresh token expired. Please login again.");
        }
        User user = existingToken.getUser();
        if (!user.isEnabled()) {
            throw new TokenRefreshException("User account is disabled");
        }

        // ROTATION
        refreshTokenRepository.delete(existingToken);
        String newAccessToken = jwtService.generateAccessToken(user);
        String newRefreshToken = createRefreshToken(user);
        return new AuthResult(newAccessToken, newRefreshToken, userMapper.toDto(user));
    }

    @Override
    @Transactional
    public void logout(String incomingRefreshToken) {
        if (incomingRefreshToken == null) return;
        String tokenHash = TokenHashUtil.hashToken(incomingRefreshToken);
        refreshTokenRepository.deleteByTokenHash(tokenHash);
        SecurityContextHolder.clearContext();
    }

    @Override
    @Transactional
    public void requestPasswordReset(String email) {
        userRepository.findByEmail(email).ifPresent(user -> {
            // Generate Token
            String rawToken = UUID.randomUUID().toString();
            String hashedToken = TokenHashUtil.hashToken(rawToken);
            // Save to DB
            user.setPasswordResetToken(hashedToken);
            user.setPasswordResetTokenExpiry(LocalDateTime.now().plusMinutes(resetPasswordExpirationMinutes)); // Short expiry 15 min
            userRepository.save(user);
            // Send Email (Async Event)
            eventPublisher.publishEvent(new PasswordResetRequestedEvent(user, rawToken));
        });
    }

    @Override
    @Transactional
    public void resetPassword(String token, String newPassword) {
        // Hash incoming token to find user
        String hashedToken = TokenHashUtil.hashToken(token);
        User user = userRepository.findByPasswordResetToken(hashedToken)
                .orElseThrow(() -> new ResourceNotFoundException("Invalid or expired password reset token"));
        // Check Expiry
        if (user.getPasswordResetTokenExpiry().isBefore(LocalDateTime.now())) {
            throw new LinkExpiredException("Password reset token has expired");
        }
        // Update Password
        user.setPassword(passwordEncoder.encode(newPassword));
        // Clear Token fields
        user.setPasswordResetToken(null);
        user.setPasswordResetTokenExpiry(null);

        userRepository.save(user);

        // SECURITY CRITICAL: Revoke all existing sessions (Refresh Tokens)
        // This kicks the hacker (or the user) out of all devices, forcing a re-login with the new password.
        refreshTokenRepository.deleteByUser(user);
    }



    // --- Helper Methods ---
    private String createRefreshToken(User user) {
        String rawToken = jwtService.generateRefreshToken();
        String hashedToken = TokenHashUtil.hashToken(rawToken);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setTokenHash(hashedToken);
        refreshToken.setExpiresAt(LocalDateTime.now().plusNanos(refreshTokenDurationMs * 1000000));

        refreshTokenRepository.save(refreshToken);
        return rawToken;
    }

}