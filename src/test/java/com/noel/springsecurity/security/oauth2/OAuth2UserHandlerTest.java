package com.noel.springsecurity.security.oauth2;

import com.noel.springsecurity.entities.User;
import com.noel.springsecurity.enums.EOAuthProvider;
import com.noel.springsecurity.enums.ERole;
import com.noel.springsecurity.repositories.IUserRepository;
import com.noel.springsecurity.security.oauth2.user.OAuth2UserInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OAuth2UserHandlerTest {

    @Mock private IUserRepository userRepository;
    @Mock private OAuth2UserInfo userInfo;

    private OAuth2UserHandler handler;

    @BeforeEach
    void setUp() {
        handler = new OAuth2UserHandler(userRepository);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));
    }

    @Test
    void processOAuth2User_updatesAnExistingOAuthAccountInPlace() {
        User existing = new User();
        existing.setFirstName("Old");
        existing.setLastName("Name");

        when(userInfo.getId()).thenReturn("google-id-1");
        when(userInfo.getFirstName()).thenReturn("New");
        when(userInfo.getLastName()).thenReturn("");
        when(userRepository.findByOauthProviderAndOauthId(EOAuthProvider.GOOGLE, "google-id-1"))
                .thenReturn(Optional.of(existing));

        User result = handler.processOAuth2User(EOAuthProvider.GOOGLE, userInfo);

        assertThat(result.getFirstName()).isEqualTo("New"); // overwritten — Google sent a real value
        assertThat(result.getLastName()).isEqualTo("Name");  // kept — Google sent a blank value
        verify(userRepository, never()).findByEmail(any());
    }

    @Test
    void processOAuth2User_linksAGoogleIdentityToAMatchingLocalAccountByEmail() {
        User existingLocalUser = new User();
        existingLocalUser.setEmail("jane@example.com");
        existingLocalUser.setRole(ERole.USER);

        when(userInfo.getId()).thenReturn("google-id-2");
        when(userInfo.getEmail()).thenReturn("jane@example.com");
        when(userRepository.findByOauthProviderAndOauthId(EOAuthProvider.GOOGLE, "google-id-2"))
                .thenReturn(Optional.empty());
        when(userRepository.findByEmail("jane@example.com")).thenReturn(Optional.of(existingLocalUser));

        User result = handler.processOAuth2User(EOAuthProvider.GOOGLE, userInfo);

        assertThat(result.getOauthProvider()).isEqualTo(EOAuthProvider.GOOGLE);
        assertThat(result.getOauthId()).isEqualTo("google-id-2");
        assertThat(result.getRole()).isEqualTo(ERole.USER); // untouched — pre-existing local account
    }

    @Test
    void processOAuth2User_registersABrandNewUserWhenNothingMatches() {
        when(userInfo.getId()).thenReturn("google-id-3");
        when(userInfo.getEmail()).thenReturn("new.person@example.com");
        when(userInfo.getFirstName()).thenReturn(null); // Google doesn't always supply this
        when(userInfo.getLastName()).thenReturn("Smith");
        when(userRepository.findByOauthProviderAndOauthId(EOAuthProvider.GOOGLE, "google-id-3"))
                .thenReturn(Optional.empty());
        when(userRepository.findByEmail("new.person@example.com")).thenReturn(Optional.empty());

        User result = handler.processOAuth2User(EOAuthProvider.GOOGLE, userInfo);

        assertThat(result.getFirstName()).isEqualTo(""); // null name handled safely, never stored as null
        assertThat(result.getLastName()).isEqualTo("Smith");
        assertThat(result.getRole()).isEqualTo(ERole.USER);
        assertThat(result.isEnabled()).isTrue();
        assertThat(result.getEmail()).isEqualTo("new.person@example.com");
    }
}