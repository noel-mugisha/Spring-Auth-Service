package com.noel.springsecurity.security.jwt;

import com.noel.springsecurity.entities.User;
import com.noel.springsecurity.enums.ERole;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class JwtServiceTest {

    // A throwaway 256-bit+ key for tests only — never use this in a real environment.
    private static final String TEST_SECRET = Base64.getEncoder().encodeToString(
            "test-secret-key-must-be-at-least-32-bytes-long!".getBytes(StandardCharsets.UTF_8)
    );

    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();
        ReflectionTestUtils.setField(jwtService, "secretKey", TEST_SECRET);
        ReflectionTestUtils.setField(jwtService, "accessTokenExpiration", 900_000L);
        ReflectionTestUtils.setField(jwtService, "registrationTokenExpiration", 600_000L);
        ReflectionTestUtils.setField(jwtService, "mfaTokenExpiration", 300_000L);
    }

    private User aUser() {
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setEmail("jane@example.com");
        user.setRole(ERole.USER);
        return user;
    }

    @Test
    void generateAccessToken_carriesTheUserIdAsSubject() {
        User user = aUser();

        String token = jwtService.generateAccessToken(user);

        assertThat(jwtService.extractUserSubject(token)).isEqualTo(user.getId().toString());
    }

    @Test
    void generateAccessToken_isNotMistakenForARegistrationOrMfaToken() {
        String token = jwtService.generateAccessToken(aUser());

        assertThat(jwtService.isRegistrationToken(token)).isFalse();
        assertThat(jwtService.isMfaChallengeToken(token)).isFalse();
    }

    @Test
    void generateRegistrationToken_carriesTheEmailAsSubject() {
        String token = jwtService.generateRegistrationToken("jane@example.com");

        assertThat(jwtService.extractUserSubject(token)).isEqualTo("jane@example.com");
        assertThat(jwtService.isRegistrationToken(token)).isTrue();
        assertThat(jwtService.isMfaChallengeToken(token)).isFalse();
    }

    @Test
    void generateMfaChallengeToken_carriesTheUserIdAsSubject() {
        UUID userId = UUID.randomUUID();

        String token = jwtService.generateMfaChallengeToken(userId);

        assertThat(jwtService.extractUserSubject(token)).isEqualTo(userId.toString());
        assertThat(jwtService.isMfaChallengeToken(token)).isTrue();
        assertThat(jwtService.isRegistrationToken(token)).isFalse();
    }

    @Test
    void isTokenExpired_falseForAFreshToken() {
        String token = jwtService.generateAccessToken(aUser());

        assertThat(jwtService.isTokenExpired(token)).isFalse();
    }

    @Test
    void isTokenExpired_trueOnceTheExpirationHasPassed() {
        ReflectionTestUtils.setField(jwtService, "accessTokenExpiration", -1000L);

        String token = jwtService.generateAccessToken(aUser());

        // Assert that JJWT automatically catches the expiration and throws an ExpiredJwtException
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> jwtService.isTokenExpired(token))
                .isInstanceOf(io.jsonwebtoken.ExpiredJwtException.class)
                .hasMessageContaining("JWT expired");
    }

    @Test
    void isMfaChallengeToken_falseOnceItHasExpired() {
        ReflectionTestUtils.setField(jwtService, "mfaTokenExpiration", -1000L);

        String expiredToken = jwtService.generateMfaChallengeToken(UUID.randomUUID());

        assertThat(jwtService.isMfaChallengeToken(expiredToken)).isFalse();
    }

    @Test
    void isMfaChallengeToken_falseForGarbageInput() {
        assertThat(jwtService.isMfaChallengeToken("not-a-real-jwt")).isFalse();
    }

    @Test
    void isTokenValid_trueWhenTheSubjectMatchesTheGivenUserPrincipal() {
        User user = aUser();
        String token = jwtService.generateAccessToken(user);

        assertThat(jwtService.isTokenValid(token, new com.noel.springsecurity.security.UserPrincipal(user)))
                .isTrue();
    }

    @Test
    void isTokenValid_falseWhenTheSubjectBelongsToADifferentUser() {
        String token = jwtService.generateAccessToken(aUser());
        User someoneElse = aUser(); // different random id

        assertThat(jwtService.isTokenValid(token, new com.noel.springsecurity.security.UserPrincipal(someoneElse)))
                .isFalse();
    }
}