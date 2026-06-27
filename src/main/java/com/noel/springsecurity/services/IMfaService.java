package com.noel.springsecurity.services;

import com.noel.springsecurity.entities.User;

import java.util.List;

public interface IMfaService {

    MfaSetupResult setupMfa(User user);

    List<String> enableMfa(User user, String code);

    void disableMfa(User user, String currentPassword);

    boolean isValidTotpCode(String secret, String code);

    boolean redeemRecoveryCode(User user, String code);

    /**
     * Data carrier for a freshly generated (not-yet-confirmed) MFA secret.
     */
    record MfaSetupResult(String secret, String qrCodeImageDataUri) {}
}