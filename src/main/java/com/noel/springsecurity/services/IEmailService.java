package com.noel.springsecurity.services;

public interface IEmailService {
    void sendVerificationEmail(String to, String username, String verificationLink);
}