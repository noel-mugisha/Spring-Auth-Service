package com.noel.springsecurity.security.oauth2;

import com.noel.springsecurity.entities.User;
import com.noel.springsecurity.enums.EOAuthProvider;
import com.noel.springsecurity.security.UserPrincipal;
import com.noel.springsecurity.security.oauth2.user.OAuth2UserInfo;
import com.noel.springsecurity.security.oauth2.user.OAuth2UserInfoFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

/**
 * Handles non-OIDC OAuth2 authentication (GitHub, Facebook, etc.)
 * Delegates user management to OAuth2UserHandler.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final OAuth2UserHandler oAuth2UserHandler;


    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        try {
            return processOAuth2User(userRequest, oAuth2User);
        } catch (Exception ex) {
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest userRequest, OAuth2User oAuth2User) {
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        // Extract user info using factory
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(
                registrationId,
                oAuth2User.getAttributes()
        );
        if (!StringUtils.hasText(oAuth2UserInfo.getEmail())) {
            throw new OAuth2AuthenticationException("Email not found from OAuth2 provider");
        }
        EOAuthProvider provider = EOAuthProvider.valueOf(registrationId.toUpperCase());
        User user = oAuth2UserHandler.processOAuth2User(provider, oAuth2UserInfo);
        // Return UserPrincipal with OAuth2 data
        return new UserPrincipal(user, oAuth2User.getAttributes());
    }
}