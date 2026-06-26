package com.noel.springsecurity.dto.request;

import jakarta.validation.constraints.NotBlank;

public record MfaDisableRequest(
        @NotBlank(message = "Password is required")
        String password
) {
}