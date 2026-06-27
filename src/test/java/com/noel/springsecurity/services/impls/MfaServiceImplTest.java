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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class MfaServiceImplTest {

    @Mock private SecretGenerator secretGenerator;
    @Mock private QrGenerator qrGenerator;
    @Mock private CodeVerifier codeVerifier;
    @Mock private RecoveryCodeGenerator recoveryCodeGenerator;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private IUserRepository userRepository;
    @Mock private IMfaRecoveryCodeRepository recoveryCodeRepository;

    @Captor private ArgumentCaptor<List<MfaRecoveryCode>> recoveryCodesCaptor;

    private MfaServiceImpl mfaService;
    private User user;

    @BeforeEach
    void setUp() {
        mfaService = new MfaServiceImpl(
                secretGenerator, qrGenerator, codeVerifier, recoveryCodeGenerator,
                passwordEncoder, userRepository, recoveryCodeRepository
        );
        ReflectionTestUtils.setField(mfaService, "issuerName", "SpringSecurityApp");

        user = new User();
        user.setEmail("jane@example.com");
        user.setPassword("hashed-password");
        user.setMfaEnabled(false);
    }

    @Test
    void setupMfa_generatesAndPersistsANewSecret() throws QrGenerationException {
        when(secretGenerator.generate()).thenReturn("SECRET123");
        when(qrGenerator.generate(any(QrData.class))).thenReturn(new byte[]{1, 2, 3});
        when(qrGenerator.getImageMimeType()).thenReturn("image/png");

        IMfaService.MfaSetupResult result = mfaService.setupMfa(user);

        assertThat(result.secret()).isEqualTo("SECRET123");
        assertThat(result.qrCodeImageDataUri()).startsWith("data:image/png;base64,");
        assertThat(user.getMfaSecret()).isEqualTo("SECRET123");
        verify(userRepository).save(user);
    }

    @Test
    void setupMfa_blocksReSetupWhileMfaIsAlreadyActive() {
        user.setMfaEnabled(true);

        assertThatThrownBy(() -> mfaService.setupMfa(user))
                .isInstanceOf(MfaAlreadyEnabledException.class);

        verifyNoInteractions(secretGenerator, qrGenerator);
    }

    @Test
    void enableMfa_rejectsConfirmationIfSetupWasNeverStarted() {
        user.setMfaSecret(null);

        assertThatThrownBy(() -> mfaService.enableMfa(user, "123456"))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    void enableMfa_rejectsAnIncorrectConfirmationCode() {
        user.setMfaSecret("SECRET123");
        when(codeVerifier.isValidCode("SECRET123", "000000")).thenReturn(false);

        assertThatThrownBy(() -> mfaService.enableMfa(user, "000000"))
                .isInstanceOf(BadCredentialsException.class);

        verify(userRepository, never()).save(any());
    }

    @Test
    void enableMfa_turnsOnMfaAndIssuesHashedRecoveryCodes() {
        user.setMfaSecret("SECRET123");
        when(codeVerifier.isValidCode("SECRET123", "654321")).thenReturn(true);
        when(recoveryCodeGenerator.generateCodes(10))
                .thenReturn(new String[]{"aaaa-bbbb", "cccc-dddd"});

        List<String> displayed = mfaService.enableMfa(user, "654321");

        assertThat(user.isMfaEnabled()).isTrue();
        assertThat(displayed).containsExactly("aaaa-bbbb", "cccc-dddd");
        verify(recoveryCodeRepository).deleteByUser(user);

        verify(recoveryCodeRepository).saveAll(recoveryCodesCaptor.capture());
        List<MfaRecoveryCode> saved = recoveryCodesCaptor.getValue();

        assertThat(saved).hasSize(2);
        assertThat(saved.get(0).getCodeHash()).isEqualTo(TokenHashUtil.hashToken("aaaabbbb"));
        assertThat(saved.get(1).getCodeHash()).isEqualTo(TokenHashUtil.hashToken("ccccdddd"));
    }

    @Test
    void disableMfa_rejectsAnIncorrectPassword() {
        when(passwordEncoder.matches("wrong", "hashed-password")).thenReturn(false);

        assertThatThrownBy(() -> mfaService.disableMfa(user, "wrong"))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    void disableMfa_rejectsOAuthOnlyAccountsThatHaveNoPassword() {
        user.setPassword(null);

        assertThatThrownBy(() -> mfaService.disableMfa(user, "anything"))
                .isInstanceOf(BadCredentialsException.class);

        verifyNoInteractions(passwordEncoder);
    }

    @Test
    void disableMfa_clearsTheSecretAndAllRecoveryCodesOnSuccess() {
        user.setMfaEnabled(true);
        user.setMfaSecret("SECRET123");
        when(passwordEncoder.matches("correct", "hashed-password")).thenReturn(true);

        mfaService.disableMfa(user, "correct");

        assertThat(user.isMfaEnabled()).isFalse();
        assertThat(user.getMfaSecret()).isNull();
        verify(recoveryCodeRepository).deleteByUser(user);
    }

    @Test
    void isValidTotpCode_delegatesToTheLibraryVerifier() {
        when(codeVerifier.isValidCode("SECRET123", "111111")).thenReturn(true);

        assertThat(mfaService.isValidTotpCode("SECRET123", "111111")).isTrue();
    }

    @Test
    void isValidTotpCode_falseWhenThereIsNoSecretYet() {
        assertThat(mfaService.isValidTotpCode(null, "111111")).isFalse();
        verifyNoInteractions(codeVerifier);
    }

    @Test
    void redeemRecoveryCode_consumesAMatchingCodeExactlyOnce() {
        MfaRecoveryCode stored = new MfaRecoveryCode();
        stored.setUser(user);
        stored.setCodeHash(TokenHashUtil.hashToken("aaaabbbb"));

        when(recoveryCodeRepository.findByUserAndCodeHash(user, TokenHashUtil.hashToken("aaaabbbb")))
                .thenReturn(Optional.of(stored));

        boolean result = mfaService.redeemRecoveryCode(user, "AAAA-BBBB"); // case/dash-insensitive

        assertThat(result).isTrue();
        verify(recoveryCodeRepository).delete(stored);
    }

    @Test
    void redeemRecoveryCode_returnsFalseForAnUnknownCode() {
        when(recoveryCodeRepository.findByUserAndCodeHash(any(), any())).thenReturn(Optional.empty());

        boolean result = mfaService.redeemRecoveryCode(user, "ffff-ffff");

        assertThat(result).isFalse();
        verify(recoveryCodeRepository, never()).delete(any());
    }
}