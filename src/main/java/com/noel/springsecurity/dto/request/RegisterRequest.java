package com.noel.springsecurity.dto.request;

import com.noel.springsecurity.validation.LowerCase;
import com.noel.springsecurity.validation.Password;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record RegisterRequest (
        @NotBlank(message = "Full name is required")
        String fullName,

        @NotBlank(message = "Email is required")
        @Email(message = "Invalid email format")
        @LowerCase
        String email,

        @NotBlank(message = "Password is required")
        @Password
        String password
) {}
