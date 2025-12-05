package com.noel.springsecurity.utils;

import com.noel.springsecurity.entities.User;
import com.noel.springsecurity.enums.ERole;
import com.noel.springsecurity.repositories.IUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Component
@RequiredArgsConstructor
@Slf4j
public class AdminSeeder implements CommandLineRunner {

    private final IUserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.seed.enabled}")
    private boolean seedEnabled;

    @Value("${app.seed.admin.email}")
    private String adminEmail;

    @Value("${app.seed.admin.password}")
    private String adminPassword;

    @Override
    @Transactional
    public void run(String... args) throws Exception {
        if (!seedEnabled) {
            log.info("Data seeding is disabled.");
            return;
        }

        createAdmin();
    }

    private void createAdmin() {
        Optional<User> existingAdmin = userRepository.findByEmail(adminEmail);

        if (existingAdmin.isPresent()) {
            log.info("Admin user ({}) already exists. Skipping seeding.", adminEmail);
            return;
        }
        log.info("Seeding Admin User...");

        User admin = new User();

        admin.setFirstName("System");
        admin.setLastName("Administrator");
        admin.setEmail(adminEmail);
        admin.setPassword(passwordEncoder.encode(adminPassword));
        admin.setRole(ERole.ADMIN);
        admin.setEnabled(true);
        userRepository.save(admin);

        log.info("Admin User created successfully! Email: {}", adminEmail);
    }
}