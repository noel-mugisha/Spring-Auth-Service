package com.noel.springsecurity.services;

public interface IEmailService {

    void sendOtpEmail(String to, String otpCode);

    void sendPasswordResetEmail(String to, String username, String resetLink);
}