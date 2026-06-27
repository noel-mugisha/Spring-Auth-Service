package com.noel.springsecurity.dto.response;

public record MfaChallengeResponse(
        boolean mfaRequired,
        String mfaToken
) {}