package com.noel.springsecurity.controllers;

import com.noel.springsecurity.dto.UserDto;
import com.noel.springsecurity.services.IUserService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserControllerTest {

    @Mock private IUserService userService;

    @Test
    void getCurrentUser_returnsTheCallersOwnProfile() {
        UserDto me = new UserDto(UUID.randomUUID(), "Jane", "Doe", "jane@example.com", "USER", false);
        when(userService.getCurrentUserProfile()).thenReturn(me);

        ResponseEntity<UserDto> response = new UserController(userService).getCurrentUser();

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).isEqualTo(me);
    }

    @Test
    void getAllUsers_returnsWhateverTheServiceReturns() {
        UserDto admin = new UserDto(UUID.randomUUID(), "Admin", "User", "admin@company.com", "ADMIN", false);
        when(userService.getAllUsers()).thenReturn(List.of(admin));

        ResponseEntity<List<UserDto>> response = new UserController(userService).getAllUsers();

        assertThat(response.getBody()).containsExactly(admin);
    }

    // IMPORTANT GAP: @PreAuthorize("hasRole('ADMIN')") on getAllUsers() is enforced by a Spring AOP
    // proxy that only exists in a real Spring context — calling the method directly on a plain
    // `new UserController(...)`, like this test does, bypasses it entirely. This test proves the
    // controller logic is correct; it does NOT prove a regular USER is blocked from this endpoint.
    // That specific guarantee can only be verified with a live HTTP call — log in as a non-admin
    // and confirm GET /api/v1/users returns 403. Put that on the Postman checklist explicitly.
}