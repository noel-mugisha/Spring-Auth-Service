package com.noel.springsecurity.dto.response;

public record MfaSetupResponse(
        String secret,
        String qrCodeImageDataUri
) {
}