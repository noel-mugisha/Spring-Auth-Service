package com.noel.springsecurity.security.oauth2;

import com.noel.springsecurity.entities.User;
import com.noel.springsecurity.enums.EOAuthProvider;
import com.noel.springsecurity.security.UserPrincipal;
import com.noel.springsecurity.security.oauth2.user.OAuth2UserInfo;
import com.noel.springsecurity.security.oauth2.user.OAuth2UserInfoFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

/**
 * Handles OIDC authentication (Google, Auth0, Okta, etc.)
 * Delegates user management to OAuth2UserHandler.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOidcUserService extends OidcUserService {
    private final OAuth2UserHandler oAuth2UserHandler;

    @Override
    @Transactional
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = super.loadUser(userRequest);
        try {
            return processOidcUser(userRequest, oidcUser);
        } catch (Exception ex) {
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    private OidcUser processOidcUser(OidcUserRequest userRequest, OidcUser oidcUser) {
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        // Extract user info using factory
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(
                registrationId,
                oidcUser.getAttributes()
        );
        if (!StringUtils.hasText(oAuth2UserInfo.getEmail())) {
            throw new OAuth2AuthenticationException("Email not found from OIDC provider");
        }
        EOAuthProvider provider = EOAuthProvider.valueOf(registrationId.toUpperCase());
        User user = oAuth2UserHandler.processOAuth2User(provider, oAuth2UserInfo);
        return new UserPrincipal(user, oidcUser.getAttributes(), oidcUser.getIdToken(), oidcUser.getUserInfo());
    }
}