package com.noel.springsecurity.events;

import com.noel.springsecurity.services.IEmailService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class PasswordResetListener implements ApplicationListener<PasswordResetRequestedEvent> {
    private final IEmailService emailService;
    @Value("${app.security.email.reset-password-url}")
    private String resetPasswordUrl;


    @Override
    public void onApplicationEvent(PasswordResetRequestedEvent event) {
        String link = resetPasswordUrl + "?token=" + event.getRawToken();
        String fullName = event.getUser().getFirstName() + " " + event.getUser().getLastName();
        emailService.sendPasswordResetEmail(
                event.getUser().getEmail(),
                fullName,
                link
        );
    }
}