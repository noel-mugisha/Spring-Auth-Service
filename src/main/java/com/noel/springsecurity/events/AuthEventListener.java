package com.noel.springsecurity.events;

import com.noel.springsecurity.services.IEmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthEventListener {

    private final IEmailService emailService;

    @Async
    @EventListener
    public void handleSendOtp(SendOtpEvent event) {
        log.info("Async processing: Sending OTP to {}", event.email());
        emailService.sendOtpEmail(event.email(), event.otpCode());
    }

    @Async
    @EventListener
    public void handlePasswordReset(PasswordResetEvent event) {
        log.info("Async processing: Sending password reset to {}", event.email());
        emailService.sendPasswordResetEmail(event.email(), event.username(), event.resetLink());
    }
}