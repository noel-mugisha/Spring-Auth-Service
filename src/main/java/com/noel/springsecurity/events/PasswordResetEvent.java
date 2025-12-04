package com.noel.springsecurity.events;

public record PasswordResetEvent(
        String email,
        String username,
        String resetLink
) {}