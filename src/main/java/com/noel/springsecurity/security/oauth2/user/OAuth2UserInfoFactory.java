package com.noel.springsecurity.security.oauth2.user;

import com.noel.springsecurity.enums.EOAuthProvider;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

import java.util.Map;

public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if (registrationId.equalsIgnoreCase(EOAuthProvider.GOOGLE.name())) {
            return new GoogleOAuth2UserInfo(attributes);
        }
        // Future: else if (GITHUB) return new GithubOAuth2UserInfo(attributes); (or any other OAuth2 provider)
        else {
            throw new OAuth2AuthenticationException("Sorry! Login with " + registrationId + " is not supported yet.");
        }
    }
}