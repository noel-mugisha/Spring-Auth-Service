package com.noel.springsecurity.utils;

import com.noel.springsecurity.entities.User;
import com.noel.springsecurity.enums.ERole;
import com.noel.springsecurity.repositories.IUserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AdminSeederTest {

    @Mock private IUserRepository userRepository;
    @Mock private PasswordEncoder passwordEncoder;

    private AdminSeeder adminSeeder;

    @BeforeEach
    void setUp() {
        adminSeeder = new AdminSeeder(userRepository, passwordEncoder);
        ReflectionTestUtils.setField(adminSeeder, "adminEmail", "admin@company.com");
        ReflectionTestUtils.setField(adminSeeder, "adminPassword", "ChangeMe123!");
    }

    @Test
    void run_doesNothingWhenSeedingIsDisabled() throws Exception {
        ReflectionTestUtils.setField(adminSeeder, "seedEnabled", false);

        adminSeeder.run();

        verifyNoInteractions(userRepository, passwordEncoder);
    }

    @Test
    void run_skipsCreationWhenAnAdminAlreadyExists() throws Exception {
        ReflectionTestUtils.setField(adminSeeder, "seedEnabled", true);
        when(userRepository.findByEmail("admin@company.com")).thenReturn(Optional.of(new User()));

        adminSeeder.run();

        verify(userRepository, never()).save(any());
        verifyNoInteractions(passwordEncoder);
    }

    @Test
    void run_createsAnEnabledAdminWithAnEncodedPasswordWhenNoneExists() throws Exception {
        ReflectionTestUtils.setField(adminSeeder, "seedEnabled", true);
        when(userRepository.findByEmail("admin@company.com")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("ChangeMe123!")).thenReturn("encoded-password");

        adminSeeder.run();

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        User saved = captor.getValue();

        assertThat(saved.getEmail()).isEqualTo("admin@company.com");
        assertThat(saved.getPassword()).isEqualTo("encoded-password");
        assertThat(saved.getRole()).isEqualTo(ERole.ADMIN);
        assertThat(saved.isEnabled()).isTrue();
    }
}