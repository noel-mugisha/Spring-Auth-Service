package com.noel.springsecurity.dto.request;

import jakarta.validation.constraints.NotBlank;

public record MfaLoginVerifyRequest(
        @NotBlank(message = "MFA token is required")
        String mfaToken,
        @NotBlank(message = "Code is required")
        String code
) {
}