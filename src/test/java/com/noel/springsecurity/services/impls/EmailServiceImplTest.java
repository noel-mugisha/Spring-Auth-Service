package com.noel.springsecurity.services.impls;

import jakarta.mail.Multipart;
import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.MailSendException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EmailServiceImplTest {

    @Mock private JavaMailSender mailSender;

    private EmailServiceImpl emailService;

    @BeforeEach
    void setUp() {
        emailService = new EmailServiceImpl(mailSender);
        ReflectionTestUtils.setField(emailService, "fromEmail", "noreply@secureapp.com");
        // MimeMessageHelper needs a genuine MimeMessage instance to write into.
        when(mailSender.createMimeMessage())
                .thenReturn(new MimeMessage(Session.getDefaultInstance(new Properties())));
    }

    @Test
    void sendOtpEmail_setsTheRecipientSubjectAndEmbedsTheCode() throws Exception {
        emailService.sendOtpEmail("jane@example.com", "482913");

        MimeMessage sent = captureSentMessage();
        assertThat(sent.getAllRecipients()[0].toString()).isEqualTo("jane@example.com");
        assertThat(sent.getSubject()).contains("Verification Code");
        assertThat(extractHtmlBody(sent)).contains("482913");
    }

    @Test
    void sendPasswordResetEmail_setsTheRecipientSubjectAndEmbedsTheLink() throws Exception {
        emailService.sendPasswordResetEmail(
                "jane@example.com", "Jane", "https://app.example.com/reset?token=abc");

        MimeMessage sent = captureSentMessage();
        assertThat(sent.getAllRecipients()[0].toString()).isEqualTo("jane@example.com");
        assertThat(sent.getSubject()).contains("Reset Your Password");
        assertThat(extractHtmlBody(sent)).contains("https://app.example.com/reset?token=abc");
        assertThat(extractHtmlBody(sent)).contains("Jane");
    }

    @Test
    void sendOtpEmail_logsAndSwallowsATransportFailureInsteadOfCrashingTheCaller() {
        doThrow(new MailSendException("smtp down")).when(mailSender).send(any(MimeMessage.class));

        // EmailServiceImpl now explicitly catches MailException alongside MessagingException —
        // a real SMTP outage must never escape this method. It only ever runs inside an @Async
        // listener, so an uncaught exception here has no one watching for it; it just fails
        // silently from the person's point of view instead of being logged clearly like this.
        assertDoesNotThrow(() -> emailService.sendOtpEmail("jane@example.com", "123456"));
    }

    private MimeMessage captureSentMessage() {
        ArgumentCaptor<MimeMessage> captor = ArgumentCaptor.forClass(MimeMessage.class);
        verify(mailSender).send(captor.capture());
        return captor.getValue();
    }

    private static String extractHtmlBody(MimeMessage message) throws Exception {
        return extractHtmlBody(message.getContent());
    }

    private static String extractHtmlBody(Object content) throws Exception {
        if (content instanceof String text) {
            return text;
        }
        if (content instanceof Multipart multipart) {
            for (int i = 0; i < multipart.getCount(); i++) {
                String found = extractHtmlBody(multipart.getBodyPart(i).getContent());
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }
}