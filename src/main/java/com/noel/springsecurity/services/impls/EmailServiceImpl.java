package com.noel.springsecurity.services.impls;

import com.noel.springsecurity.services.IEmailService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailServiceImpl implements IEmailService {
    private final JavaMailSender mailSender;
    @Value("${spring.mail.username}")
    private String fromEmail;


    @Async
    @Override
    public void sendVerificationEmail(String to, String username, String verificationLink) {
        try {
            log.info("Starting email sending process for {}", to);
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, MimeMessageHelper.MULTIPART_MODE_MIXED_RELATED, StandardCharsets.UTF_8.name());

            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject("Verify your email address");

            String htmlContent = buildVerificationEmailTemplate(username, verificationLink);
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("Verification email successfully sent to: {}", to);

        } catch (MessagingException e) {
            log.error("Failed to send verification email to {}: {}", to, e.getMessage());
        }
    }

    @Async
    @Override
    public void sendPasswordResetEmail(String to, String username, String resetLink) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, MimeMessageHelper.MULTIPART_MODE_MIXED_RELATED, StandardCharsets.UTF_8.name());

            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject("Reset your password");

            String htmlContent = buildPasswordResetEmailTemplate(username, resetLink);
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("Password reset email sent to: {}", to);
        } catch (MessagingException e) {
            log.error("Failed to send password reset email", e);
        }
    }


    private String buildVerificationEmailTemplate(String username, String link) {
        return """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Verify Your Email</title>
            </head>
            <body style="margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;background-color:#f4f4f7;">
                <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0" style="background-color:#f4f4f7;">
                    <tr>
                        <td style="padding:40px 20px;">
                            <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0" style="max-width:600px;margin:0 auto;background-color:#ffffff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.05);">
                                <!-- Header -->
                                <tr>
                                    <td style="padding:40px 40px 30px;text-align:center;border-bottom:1px solid #e8e8e8;">
                                        <h1 style="margin:0;font-size:24px;font-weight:600;color:#1a1a1a;">SecureApp</h1>
                                    </td>
                                </tr>
                                
                                <!-- Content -->
                                <tr>
                                    <td style="padding:40px;">
                                        <h2 style="margin:0 0 16px;font-size:20px;font-weight:600;color:#1a1a1a;">Verify your email address</h2>
                                        <p style="margin:0 0 16px;font-size:16px;line-height:24px;color:#4a4a4a;">Hi %s,</p>
                                        <p style="margin:0 0 24px;font-size:16px;line-height:24px;color:#4a4a4a;">Thanks for signing up! Please verify your email address by clicking the button below to activate your account.</p>
                                        
                                        <!-- CTA Button -->
                                        <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0">
                                            <tr>
                                                <td style="padding:0 0 24px;">
                                                    <a href="%s" style="display:inline-block;padding:14px 32px;background-color:#5469d4;color:#ffffff;text-decoration:none;border-radius:6px;font-size:16px;font-weight:600;text-align:center;">Verify Email Address</a>
                                                </td>
                                            </tr>
                                        </table>
                                        
                                        <!-- Alternative Link -->
                                        <p style="margin:0 0 16px;font-size:14px;line-height:20px;color:#6b7280;">Or copy and paste this link into your browser:</p>
                                        <p style="margin:0 0 24px;font-size:14px;line-height:20px;color:#5469d4;word-break:break-all;">%s</p>
                                        
                                        <!-- Expiry Notice -->
                                        <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0" style="background-color:#f9fafb;border-radius:6px;padding:16px;margin:0 0 24px;">
                                            <tr>
                                                <td style="font-size:14px;line-height:20px;color:#6b7280;">
                                                    ⏱️ This verification link will expire in <strong>24 hours</strong> for security reasons.
                                                </td>
                                            </tr>
                                        </table>
                                        
                                        <p style="margin:0;font-size:14px;line-height:20px;color:#6b7280;">If you didn't create an account with us, you can safely ignore this email.</p>
                                    </td>
                                </tr>
                                
                                <!-- Footer -->
                                <tr>
                                    <td style="padding:30px 40px;background-color:#f9fafb;border-top:1px solid #e8e8e8;border-radius:0 0 8px 8px;">
                                        <p style="margin:0 0 8px;font-size:13px;line-height:18px;color:#9ca3af;">Questions? Contact us at support@secureapp.com</p>
                                        <p style="margin:0;font-size:13px;line-height:18px;color:#9ca3af;">© 2024 SecureApp. All rights reserved.</p>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </table>
            </body>
            </html>
            """.formatted(username, link, link);
    }

    private String buildPasswordResetEmailTemplate(String username, String resetLink) {
        return """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Reset Your Password</title>
            </head>
            <body style="margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;background-color:#f4f4f7;">
                <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0" style="background-color:#f4f4f7;">
                    <tr>
                        <td style="padding:40px 20px;">
                            <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0" style="max-width:600px;margin:0 auto;background-color:#ffffff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.05);">
                                <!-- Header -->
                                <tr>
                                    <td style="padding:40px 40px 30px;text-align:center;border-bottom:1px solid #e8e8e8;">
                                        <h1 style="margin:0;font-size:24px;font-weight:600;color:#1a1a1a;">SecureApp</h1>
                                    </td>
                                </tr>
                                
                                <!-- Content -->
                                <tr>
                                    <td style="padding:40px;">
                                        <h2 style="margin:0 0 16px;font-size:20px;font-weight:600;color:#1a1a1a;">Reset your password</h2>
                                        <p style="margin:0 0 16px;font-size:16px;line-height:24px;color:#4a4a4a;">Hi %s,</p>
                                        <p style="margin:0 0 24px;font-size:16px;line-height:24px;color:#4a4a4a;">We received a request to reset your password. Click the button below to create a new password.</p>
                                        
                                        <!-- CTA Button -->
                                        <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0">
                                            <tr>
                                                <td style="padding:0 0 24px;">
                                                    <a href="%s" style="display:inline-block;padding:14px 32px;background-color:#5469d4;color:#ffffff;text-decoration:none;border-radius:6px;font-size:16px;font-weight:600;text-align:center;">Reset Password</a>
                                                </td>
                                            </tr>
                                        </table>
                                        
                                        <!-- Alternative Link -->
                                        <p style="margin:0 0 16px;font-size:14px;line-height:20px;color:#6b7280;">Or copy and paste this link into your browser:</p>
                                        <p style="margin:0 0 24px;font-size:14px;line-height:20px;color:#5469d4;word-break:break-all;">%s</p>
                                        
                                        <!-- Expiry Notice -->
                                        <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0" style="background-color:#fef3c7;border-left:4px solid #f59e0b;padding:16px;margin:0 0 24px;">
                                            <tr>
                                                <td style="font-size:14px;line-height:20px;color:#92400e;">
                                                    <strong>⚠️ Security Notice:</strong> This link will expire in <strong>15 minutes</strong>.
                                                </td>
                                            </tr>
                                        </table>
                                        
                                        <!-- Security Notice -->
                                        <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0" style="background-color:#f9fafb;border-radius:6px;padding:16px;margin:0 0 24px;">
                                            <tr>
                                                <td style="font-size:14px;line-height:20px;color:#6b7280;">
                                                    <strong>Didn't request this?</strong><br/>
                                                    If you didn't request a password reset, you can safely ignore this email. Your password will remain unchanged.
                                                </td>
                                            </tr>
                                        </table>
                                        
                                        <p style="margin:0;font-size:14px;line-height:20px;color:#9ca3af;">For security reasons, never share this link with anyone.</p>
                                    </td>
                                </tr>
                                
                                <!-- Footer -->
                                <tr>
                                    <td style="padding:30px 40px;background-color:#f9fafb;border-top:1px solid #e8e8e8;border-radius:0 0 8px 8px;">
                                        <p style="margin:0 0 8px;font-size:13px;line-height:18px;color:#9ca3af;">Questions? Contact us at support@secureapp.com</p>
                                        <p style="margin:0;font-size:13px;line-height:18px;color:#9ca3af;">© 2024 SecureApp. All rights reserved.</p>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </table>
            </body>
            </html>
            """.formatted(username, resetLink, resetLink);
    }
}