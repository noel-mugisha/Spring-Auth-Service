package com.noel.springsecurity.dto.request;

import com.noel.springsecurity.validation.Password;
import jakarta.validation.constraints.NotBlank;

public record RegisterRequest (
        @NotBlank(message = "First name is required")
        String firstName,

        @NotBlank(message = "Last name is required")
        String lastName,

        @NotBlank(message = "Password is required")
        @Password
        String password
) {}