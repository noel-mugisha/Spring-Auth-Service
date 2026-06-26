package com.noel.springsecurity.services.impls;

import com.noel.springsecurity.entities.MfaRecoveryCode;
import com.noel.springsecurity.entities.User;
import com.noel.springsecurity.exceptions.MfaAlreadyEnabledException;
import com.noel.springsecurity.repositories.IMfaRecoveryCodeRepository;
import com.noel.springsecurity.repositories.IUserRepository;
import com.noel.springsecurity.services.IMfaService;
import com.noel.springsecurity.utils.TokenHashUtil;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.recovery.RecoveryCodeGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.List;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

@Service
@RequiredArgsConstructor
public class MfaServiceImpl implements IMfaService {

    private static final int RECOVERY_CODE_COUNT = 10;

    private final SecretGenerator secretGenerator;
    private final QrGenerator qrGenerator;
    private final CodeVerifier codeVerifier;
    private final RecoveryCodeGenerator recoveryCodeGenerator;
    private final PasswordEncoder passwordEncoder;
    private final IUserRepository userRepository;
    private final IMfaRecoveryCodeRepository recoveryCodeRepository;

    @Value("${app.security.mfa.issuer-name}")
    private String issuerName;

    @Override
    @Transactional
    public MfaSetupResult setupMfa(User user) {
        if (user.isMfaEnabled()) {
            throw new MfaAlreadyEnabledException("MFA is already enabled. Disable it before setting up a new device.");
        }

        // A fresh secret on every /setup call; it only becomes active once enableMfa() confirms it.
        String secret = secretGenerator.generate();
        user.setMfaSecret(secret);
        userRepository.save(user);

        QrData data = new QrData.Builder()
                .label(user.getEmail())
                .secret(secret)
                .issuer(issuerName)
                .digits(6)
                .period(30)
                .build();

        try {
            byte[] imageData = qrGenerator.generate(data);
            String qrCodeImageDataUri = getDataUriForImage(imageData, qrGenerator.getImageMimeType());
            return new MfaSetupResult(secret, qrCodeImageDataUri);
        } catch (QrGenerationException e) {
            throw new IllegalStateException("Failed to generate MFA QR code", e);
        }
    }

    @Override
    @Transactional
    public List<String> enableMfa(User user, String code) {
        if (user.getMfaSecret() == null) {
            throw new BadCredentialsException("MFA setup has not been started. Call /mfa/setup first.");
        }
        if (!codeVerifier.isValidCode(user.getMfaSecret(), code)) {
            throw new BadCredentialsException("Invalid authentication code.");
        }

        user.setMfaEnabled(true);
        userRepository.save(user);

        // Replace any previous batch so old codes can never be reused.
        recoveryCodeRepository.deleteByUser(user);

        List<String> displayCodes = Arrays.asList(recoveryCodeGenerator.generateCodes(RECOVERY_CODE_COUNT));
        List<MfaRecoveryCode> entities = displayCodes.stream()
                .map(displayCode -> {
                    MfaRecoveryCode entity = new MfaRecoveryCode();
                    entity.setUser(user);
                    entity.setCodeHash(TokenHashUtil.hashToken(normalize(displayCode)));
                    return entity;
                })
                .toList();
        recoveryCodeRepository.saveAll(entities);

        return displayCodes;
    }

    @Override
    @Transactional
    public void disableMfa(User user, String currentPassword) {
        if (user.getPassword() == null || !passwordEncoder.matches(currentPassword, user.getPassword())) {
            throw new BadCredentialsException("Incorrect password.");
        }

        user.setMfaEnabled(false);
        user.setMfaSecret(null);
        userRepository.save(user);
        recoveryCodeRepository.deleteByUser(user);
    }

    @Override
    public boolean isValidTotpCode(String secret, String code) {
        return secret != null && code != null && codeVerifier.isValidCode(secret, code);
    }

    @Override
    @Transactional
    public boolean redeemRecoveryCode(User user, String code) {
        if (code == null) return false;
        String hashed = TokenHashUtil.hashToken(normalize(code));
        return recoveryCodeRepository.findByUserAndCodeHash(user, hashed)
                .map(recoveryCode -> {
                    recoveryCodeRepository.delete(recoveryCode);
                    return true;
                })
                .orElse(false);
    }

    // Strip dashes/whitespace and lowercase, so "tf8i-exmo-3lcb-slkm" and "TF8IEXMO3LCBSLKM" hash the same way.
    private String normalize(String code) {
        return code.replaceAll("[^a-zA-Z0-9]", "").toLowerCase();
    }
}