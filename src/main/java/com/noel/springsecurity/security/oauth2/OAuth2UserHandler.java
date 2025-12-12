package com.noel.springsecurity.security.oauth2;

import com.noel.springsecurity.entities.User;
import com.noel.springsecurity.enums.EOAuthProvider;
import com.noel.springsecurity.enums.ERole;
import com.noel.springsecurity.repositories.IUserRepository;
import com.noel.springsecurity.security.oauth2.user.OAuth2UserInfo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class OAuth2UserHandler {
    private final IUserRepository userRepository;

    @Transactional
    public User processOAuth2User(EOAuthProvider provider, OAuth2UserInfo userInfo) {
        Optional<User> userOptional = userRepository.findByOauthProviderAndOauthId(provider, userInfo.getId());

        if (userOptional.isPresent()) {
            return updateExistingUser(userOptional.get(), userInfo);
        }

        Optional<User> userByEmail = userRepository.findByEmail(userInfo.getEmail());
        // Link a user, else create a new one
        return userByEmail.map(user ->
                        linkExistingAccount(user, provider, userInfo))
                .orElseGet(() -> registerNewUser(userInfo, provider));
    }

    private User registerNewUser(OAuth2UserInfo userInfo, EOAuthProvider provider) {
        log.info("Registering new user via {}: {}", provider, userInfo.getEmail());
        User user = new User();
        user.setOauthProvider(provider);
        user.setOauthId(userInfo.getId());
        user.setFirstName(getSafeText(userInfo.getFirstName()));
        user.setLastName(getSafeText(userInfo.getLastName()));
        user.setEmail(userInfo.getEmail());
        user.setRole(ERole.USER);
        user.setEnabled(true);
        return userRepository.save(user);
    }

    private User updateExistingUser(User existingUser, OAuth2UserInfo userInfo) {
        log.debug("Updating existing OAuth2 user: {}", existingUser.getEmail());
        if (StringUtils.hasText(userInfo.getFirstName())) {
            existingUser.setFirstName(userInfo.getFirstName());
        }
        if (StringUtils.hasText(userInfo.getLastName())) {
            existingUser.setLastName(userInfo.getLastName());
        }

        return userRepository.save(existingUser);
    }

    private User linkExistingAccount(User existingUser, EOAuthProvider provider, OAuth2UserInfo userInfo) {
        log.info("Linking existing account {} to provider {}", existingUser.getEmail(), provider);
        existingUser.setOauthProvider(provider);
        existingUser.setOauthId(userInfo.getId());
        return userRepository.save(existingUser);
    }

    /**
     * Helper to safely handle null strings.
     * Returns the text if valid, or an empty string if null.
     */
    private String getSafeText(String text) {
        return StringUtils.hasText(text) ? text : "";
    }
}