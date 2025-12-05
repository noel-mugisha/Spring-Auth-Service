package com.noel.springsecurity.repositories;

import com.noel.springsecurity.entities.EmailVerification;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface IEmailVerificationRepository extends JpaRepository<EmailVerification, String> {

    Optional<EmailVerification> findByEmail(String email);
}
