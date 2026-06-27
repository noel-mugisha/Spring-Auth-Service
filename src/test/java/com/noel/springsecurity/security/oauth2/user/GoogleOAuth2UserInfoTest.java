package com.noel.springsecurity.security.oauth2.user;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class GoogleOAuth2UserInfoTest {

    @Test
    void mapsAllStandardGoogleClaimsToTheCommonInterface() {
        Map<String, Object> attributes = Map.of(
                "sub", "1234567890",
                "name", "Jane Doe",
                "email", "jane@example.com",
                "given_name", "Jane",
                "family_name", "Doe"
        );

        GoogleOAuth2UserInfo userInfo = new GoogleOAuth2UserInfo(attributes);

        assertThat(userInfo.getId()).isEqualTo("1234567890");
        assertThat(userInfo.getName()).isEqualTo("Jane Doe");
        assertThat(userInfo.getEmail()).isEqualTo("jane@example.com");
        assertThat(userInfo.getFirstName()).isEqualTo("Jane");
        assertThat(userInfo.getLastName()).isEqualTo("Doe");
        assertThat(userInfo.getAttributes()).isEqualTo(attributes);
    }
}