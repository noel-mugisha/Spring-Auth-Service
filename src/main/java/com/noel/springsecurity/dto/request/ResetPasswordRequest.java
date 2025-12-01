package com.noel.springsecurity.dto.request;

import com.noel.springsecurity.validation.Password;
import jakarta.validation.constraints.NotBlank;

public record ResetPasswordRequest(
        @NotBlank(message = "Token is required")
        String token,

        @NotBlank(message = "New password is required")
        @Password
        String newPassword
) {}