package com.noel.springsecurity.services.impls;

import com.noel.springsecurity.dto.UserDto;
import com.noel.springsecurity.entities.User;
import com.noel.springsecurity.mappers.IUserMapper;
import com.noel.springsecurity.repositories.IUserRepository;
import com.noel.springsecurity.utils.IAuthenticationFacade;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserServiceImplTest {

    @Mock private IAuthenticationFacade authenticationFacade;
    @Mock private IUserMapper userMapper;
    @Mock private IUserRepository userRepository;

    private UserServiceImpl userService;

    @BeforeEach
    void setUp() {
        userService = new UserServiceImpl(authenticationFacade, userMapper, userRepository);
    }

    @Test
    void getCurrentUserProfile_mapsWhoeverTheFacadeSaysIsLoggedIn() {
        User currentUser = new User();
        UserDto dto = new UserDto(UUID.randomUUID(), "Jane", "Doe", "jane@example.com", "USER", false);
        when(authenticationFacade.getCurrentUser()).thenReturn(currentUser);
        when(userMapper.toDto(currentUser)).thenReturn(dto);

        assertThat(userService.getCurrentUserProfile()).isEqualTo(dto);
    }

    @Test
    void getAllUsers_mapsEveryRowInTheRepository() {
        User userA = new User();
        User userB = new User();
        UserDto dtoA = new UserDto(UUID.randomUUID(), "A", "A", "a@example.com", "USER", false);
        UserDto dtoB = new UserDto(UUID.randomUUID(), "B", "B", "b@example.com", "ADMIN", false);
        when(userRepository.findAll()).thenReturn(List.of(userA, userB));
        when(userMapper.toDto(userA)).thenReturn(dtoA);
        when(userMapper.toDto(userB)).thenReturn(dtoB);

        assertThat(userService.getAllUsers()).containsExactly(dtoA, dtoB);
    }
}