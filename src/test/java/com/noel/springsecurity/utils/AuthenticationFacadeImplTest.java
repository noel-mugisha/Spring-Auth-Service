package com.noel.springsecurity.utils;

import com.noel.springsecurity.entities.User;
import com.noel.springsecurity.exceptions.ResourceNotFoundException;
import com.noel.springsecurity.repositories.IUserRepository;
import com.noel.springsecurity.security.UserPrincipal;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthenticationFacadeImplTest {

    @Mock private IUserRepository userRepository;

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void getCurrentUser_returnsTheAuthenticatedUserFromTheDatabase() {
        UUID userId = UUID.randomUUID();
        User user = new User();
        user.setId(userId);
        user.setEmail("jane@example.com");

        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                new UserPrincipal(user), null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
        SecurityContextHolder.getContext().setAuthentication(auth);
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));

        AuthenticationFacadeImpl facade = new AuthenticationFacadeImpl(userRepository);

        assertThat(facade.getCurrentUser()).isEqualTo(user);
    }

    @Test
    void getCurrentUser_throwsWhenNoOneIsAuthenticated() {
        SecurityContextHolder.clearContext(); // no Authentication at all

        AuthenticationFacadeImpl facade = new AuthenticationFacadeImpl(userRepository);

        assertThatThrownBy(facade::getCurrentUser).isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    void getCurrentUser_throwsForAnAnonymousVisitor() {
        AnonymousAuthenticationToken anonymous = new AnonymousAuthenticationToken(
                "key", "anonymousUser", List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS")));
        SecurityContextHolder.getContext().setAuthentication(anonymous);

        AuthenticationFacadeImpl facade = new AuthenticationFacadeImpl(userRepository);

        assertThatThrownBy(facade::getCurrentUser).isInstanceOf(ResourceNotFoundException.class);
    }
}