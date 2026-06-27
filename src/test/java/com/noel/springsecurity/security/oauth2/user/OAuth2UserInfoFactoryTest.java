package com.noel.springsecurity.security.oauth2.user;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OAuth2UserInfoFactoryTest {

    @Test
    void returnsAGoogleUserInfoForTheGoogleRegistrationId() {
        OAuth2UserInfo info = OAuth2UserInfoFactory.getOAuth2UserInfo("google", Map.of("sub", "123"));

        assertThat(info).isInstanceOf(GoogleOAuth2UserInfo.class);
    }

    @Test
    void matchingIsCaseInsensitive() {
        OAuth2UserInfo info = OAuth2UserInfoFactory.getOAuth2UserInfo("GOOGLE", Map.of("sub", "123"));

        assertThat(info).isInstanceOf(GoogleOAuth2UserInfo.class);
    }

    @Test
    void rejectsAnUnsupportedProvider() {
        assertThatThrownBy(() -> OAuth2UserInfoFactory.getOAuth2UserInfo("github", Map.of()))
                .isInstanceOf(OAuth2AuthenticationException.class);
    }
}