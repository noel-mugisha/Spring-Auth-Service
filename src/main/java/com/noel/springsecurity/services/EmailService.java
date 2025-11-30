package com.noel.springsecurity.services;

public interface EmailService {
    void sendVerificationEmail(String to, String username, String verificationLink);
}