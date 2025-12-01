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

            String htmlContent = buildEmailTemplate(username, verificationLink);
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

            String htmlContent = """
                <div style="font-family:Helvetica,Arial,sans-serif;font-size:16px;margin:0;color:#0b0c0c">
                  <h3>Password Reset Request</h3>
                  <p>Hi %s,</p>
                  <p>We received a request to reset your password. Click the link below to choose a new password:</p>
                  <p><a href="%s">Reset Password</a></p>
                  <p>This link expires in 15 minutes.</p>
                  <p>If you didn't ask for this, you can safely ignore this email.</p>
                </div>
                """.formatted(username, resetLink);

            helper.setText(htmlContent, true);
            mailSender.send(message);
            log.info("Password reset email sent to: {}", to);
        } catch (MessagingException e) {
            log.error("Failed to send password reset email", e);
        }
    }


    // Helper method to build the email template
    private String buildEmailTemplate(String username, String link) {
        return """
            <div style="font-family:Helvetica,Arial,sans-serif;font-size:16px;margin:0;color:#0b0c0c">
              <table role="presentation" width="100%%" style="border-collapse:collapse;min-width:100%%;width:100%%!important" cellpadding="0" cellspacing="0" border="0">
                <tbody><tr>
                  <td width="100%%" height="53" bgcolor="#0b0c0c">
                    <table role="presentation" width="100%%" style="border-collapse:collapse;max-width:580px" cellpadding="0" cellspacing="0" border="0" align="center">
                      <tbody><tr>
                        <td width="70" bgcolor="#0b0c0c" valign="middle">
                            <span style="font-family:Helvetica,Arial,sans-serif;font-weight:700;color:#ffffff;font-size:20px;padding-left:10px">
                                SecureApp
                            </span>
                        </td>
                      </tr></tbody>
                    </table>
                  </td>
                </tr></tbody>
              </table>
              <table role="presentation" class="content" align="center" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;max-width:580px;width:100%%!important" width="100%%">
                <tbody><tr>
                  <td width="10" height="10" valign="middle"></td>
                  <td>
                    <table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse">
                      <tbody><tr>
                        <td bgcolor="#1D70B8" width="100%%" height="10"></td>
                      </tr></tbody>
                    </table>
                  </td>
                  <td width="10" valign="middle" height="10"></td>
                </tr></tbody>
              </table>
              <table role="presentation" class="content" align="center" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;max-width:580px;width:100%%!important" width="100%%">
                <tbody><tr>
                  <td height="30"><br></td>
                </tr>
                <tr>
                  <td width="10" valign="middle"><br></td>
                  <td style="font-family:Helvetica,Arial,sans-serif;font-size:19px;line-height:1.315789474;max-width:560px">
                    <p style="Margin:0 0 20px 0;font-size:19px;line-height:25px;color:#0b0c0c">Hi %s,</p>
                    <p style="Margin:0 0 20px 0;font-size:19px;line-height:25px;color:#0b0c0c"> Thank you for registering. Please click on the below link to activate your account: </p>
                    <blockquote style="Margin:0 0 20px 0;border-left:10px solid #b1b4b6;padding:15px 0 0.1px 15px;font-size:19px;line-height:25px">
                      <p style="Margin:0 0 20px 0;font-size:19px;line-height:25px;color:#0b0c0c"> <a href="%s">Activate Now</a> </p>
                    </blockquote>
                    <p>Link will expire in 24 hours.</p>
                  </td>
                  <td width="10" valign="middle"><br></td>
                </tr>
                <tr>
                  <td height="30"><br></td>
                </tr>
                </tbody>
              </table>
            </div>
            """.formatted(username, link);
    }
}