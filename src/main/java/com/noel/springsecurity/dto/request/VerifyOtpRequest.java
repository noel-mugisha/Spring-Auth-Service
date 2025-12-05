package com.noel.springsecurity.dto.request;

import com.noel.springsecurity.validation.LowerCase;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record VerifyOtpRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Invalid email format")
        @LowerCase
        String email,

        @NotBlank(message = "OTP is required")
        String otp
) {}