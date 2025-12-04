package com.noel.springsecurity.services.impls;

import com.noel.springsecurity.services.IEmailService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailServiceImpl implements IEmailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String fromEmail;

    @Override
    public void sendOtpEmail(String to, String otpCode) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, MimeMessageHelper.MULTIPART_MODE_MIXED_RELATED, StandardCharsets.UTF_8.name());

            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject("SecureApp - Verification Code");

            // Inject the OTP into the template
            String htmlContent = getOtpEmailTemplate(otpCode);
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("OTP Email sent to: {}", to);

        } catch (MessagingException e) {
            log.error("Failed to send OTP email to {}: {}", to, e.getMessage());
        }
    }

    @Override
    public void sendPasswordResetEmail(String to, String username, String resetLink) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, MimeMessageHelper.MULTIPART_MODE_MIXED_RELATED, StandardCharsets.UTF_8.name());

            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject("SecureApp - Reset Your Password");

            String htmlContent = getPasswordResetTemplate(username, resetLink);
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("Password Reset Email sent to: {}", to);

        } catch (MessagingException e) {
            log.error("Failed to send reset email to {}: {}", to, e.getMessage());
        }
    }

    private String getOtpEmailTemplate(String otp) {
        // We use a "spaced" version of the OTP for better readability in the HTML
        String spacedOtp = otp.replaceAll(".(?!$)", "$0 ");

        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <style>
                        body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }
                        .container { max-width: 600px; margin: 40px auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05); }
                        .header { background: linear-gradient(135deg, #0f172a 0%%, #334155 100%%); padding: 30px; text-align: center; }
                        .header h1 { color: #ffffff; margin: 0; font-size: 24px; font-weight: 600; letter-spacing: 1px; }
                        .content { padding: 40px 30px; text-align: center; color: #334155; }
                        .icon { font-size: 48px; margin-bottom: 20px; }
                        .text-main { font-size: 16px; line-height: 1.6; margin-bottom: 30px; }
                        .otp-box { background: #f8fafc; border: 2px dashed #cbd5e1; border-radius: 8px; padding: 20px; display: inline-block; margin-bottom: 30px; }
                        .otp-code { font-family: 'Courier New', monospace; font-size: 32px; font-weight: 700; color: #0f172a; letter-spacing: 8px; }
                        .expiry { font-size: 13px; color: #64748b; margin-top: 10px; }
                        .footer { background-color: #f8fafc; padding: 20px; text-align: center; font-size: 12px; color: #94a3b8; border-top: 1px solid #e2e8f0; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>SecureApp</h1>
                        </div>
                        <div class="content">
                            <div class="icon">🔐</div>
                            <p class="text-main">
                                To ensure the security of your account, please verify your email address.
                                Use the code below to complete your registration.
                            </p>
                
                            <div class="otp-box">
                                <div class="otp-code">%s</div>
                            </div>
                
                            <p class="expiry">This code expires in 10 minutes.</p>
                            <p style="font-size: 14px; color: #64748b; margin-top: 30px;">
                                If you didn't request this code, you can safely ignore this email.
                            </p>
                        </div>
                        <div class="footer">
                            &copy; 2025 SecureApp Inc. All rights reserved.<br>
                            Kigali, Rwanda
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(otp); // Note: We pass raw OTP, CSS letter-spacing handles the look
    }

    private String getPasswordResetTemplate(String username, String link) {
        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <style>
                        body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }
                        .container { max-width: 600px; margin: 40px auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05); }
                        .header { background: linear-gradient(135deg, #0f172a 0%%, #334155 100%%); padding: 30px; text-align: center; }
                        .header h1 { color: #ffffff; margin: 0; font-size: 24px; font-weight: 600; }
                        .content { padding: 40px 30px; text-align: center; color: #334155; }
                        .text-main { font-size: 16px; line-height: 1.6; margin-bottom: 30px; }
                        .btn { display: inline-block; background: #0f172a; color: #ffffff; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: 600; margin-bottom: 30px; transition: background 0.3s; }
                        .btn:hover { background: #1e293b; }
                        .expiry { font-size: 13px; color: #64748b; }
                        .footer { background-color: #f8fafc; padding: 20px; text-align: center; font-size: 12px; color: #94a3b8; border-top: 1px solid #e2e8f0; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>SecureApp</h1>
                        </div>
                        <div class="content">
                            <h2>Reset Your Password</h2>
                            <p class="text-main">Hi %s,</p>
                            <p class="text-main">
                                We received a request to reset your password. Click the button below to choose a new one.
                            </p>
                
                            <a href="%s" class="btn">Reset Password</a>
                
                            <p class="expiry">This link expires in 15 minutes.</p>
                            <p style="font-size: 14px; color: #64748b; margin-top: 30px;">
                                If you didn't ask to reset your password, you can ignore this email.
                            </p>
                        </div>
                        <div class="footer">
                            &copy; 2025 SecureApp Inc. All rights reserved.
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(username, link);
    }
}