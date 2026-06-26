package com.noel.springsecurity.dto.response;

import java.util.List;

public record MfaRecoveryCodesResponse(
        List<String> recoveryCodes
) {
}