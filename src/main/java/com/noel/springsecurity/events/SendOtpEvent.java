package com.noel.springsecurity.events;

public record SendOtpEvent(
        String email,
        String otpCode
) {}