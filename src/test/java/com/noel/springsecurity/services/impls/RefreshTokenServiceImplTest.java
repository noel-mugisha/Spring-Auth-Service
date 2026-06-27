package com.noel.springsecurity.services.impls;

import com.noel.springsecurity.entities.RefreshToken;
import com.noel.springsecurity.entities.User;
import com.noel.springsecurity.exceptions.TokenRefreshException;
import com.noel.springsecurity.repositories.IRefreshTokenRepository;
import com.noel.springsecurity.security.jwt.JwtService;
import com.noel.springsecurity.utils.TokenHashUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceImplTest {

    @Mock private IRefreshTokenRepository refreshTokenRepository;
    @Mock private JwtService jwtService;

    private RefreshTokenServiceImpl refreshTokenService;
    private User user;

    @BeforeEach
    void setUp() {
        refreshTokenService = new RefreshTokenServiceImpl(refreshTokenRepository, jwtService);
        ReflectionTestUtils.setField(refreshTokenService, "refreshTokenDurationMs", 604_800_000L);
        user = new User();
    }

    @Test
    void createRefreshToken_storesOnlyTheHashNeverTheRawToken() {
        when(jwtService.generateRefreshToken()).thenReturn("raw-token-value");

        String returned = refreshTokenService.createRefreshToken(user);

        assertThat(returned).isEqualTo("raw-token-value"); // the raw value is what goes in the cookie

        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(captor.capture());
        RefreshToken saved = captor.getValue();

        assertThat(saved.getTokenHash()).isEqualTo(TokenHashUtil.hashToken("raw-token-value"));
        assertThat(saved.getTokenHash()).isNotEqualTo("raw-token-value"); // never stored in plaintext
        assertThat(saved.getUser()).isEqualTo(user);
        assertThat(saved.getExpiresAt()).isAfter(LocalDateTime.now());
    }

    @Test
    void findByToken_looksUpByTheHashOfWhateverWasPresented() {
        RefreshToken stored = new RefreshToken();
        when(refreshTokenRepository.findByTokenHash(TokenHashUtil.hashToken("raw-token-value")))
                .thenReturn(Optional.of(stored));

        assertThat(refreshTokenService.findByToken("raw-token-value")).contains(stored);
    }

    @Test
    void verifyExpiration_passesThroughAStillValidToken() {
        RefreshToken token = new RefreshToken();
        token.setExpiresAt(LocalDateTime.now().plusDays(1));

        assertThat(refreshTokenService.verifyExpiration(token)).isSameAs(token);
        verify(refreshTokenRepository, never()).delete(any());
    }

    @Test
    void verifyExpiration_deletesAndRejectsAnExpiredToken() {
        RefreshToken token = new RefreshToken();
        token.setExpiresAt(LocalDateTime.now().minusMinutes(1));

        assertThatThrownBy(() -> refreshTokenService.verifyExpiration(token))
                .isInstanceOf(TokenRefreshException.class);

        verify(refreshTokenRepository).delete(token);
    }

    @Test
    void deleteByToken_removesByHashNotByRawValue() {
        refreshTokenService.deleteByToken("raw-token-value");

        verify(refreshTokenRepository).deleteByTokenHash(TokenHashUtil.hashToken("raw-token-value"));
    }

    @Test
    void deleteByUser_revokesEveryTokenBelongingToThatUser() {
        refreshTokenService.deleteByUser(user);

        verify(refreshTokenRepository).deleteByUser(user);
    }
}