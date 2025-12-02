package com.noel.springsecurity.events;

import com.noel.springsecurity.entities.User;
import com.noel.springsecurity.services.IEmailService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class RegistrationListener implements ApplicationListener<RegistrationCompleteEvent> {

    private final IEmailService emailService;

    @Value("${app.security.email.verification-url}")
    private String verificationUrl;

    @Override
    public void onApplicationEvent(RegistrationCompleteEvent event) {
        User user = event.getUser();
        String token = user.getVerificationToken();

        // Construct the link: http://frontend.com/verify-email?token=xyz
        String link = verificationUrl + "?token=" + token;

        String fullName= user.getFirstName() + " " + user.getLastName();
        // Send the email
        emailService.sendVerificationEmail(user.getEmail(), fullName, link);
    }
}