package com.noel.springsecurity.repositories;

import com.noel.springsecurity.entities.User;
import com.noel.springsecurity.enums.EOAuthProvider;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface IUserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);

    Optional<User> findByPasswordResetToken(String passwordResetToken);

    // Used for OAuth2 authentication
    Optional<User> findByOauthProviderAndOauthId(EOAuthProvider oauthProvider, String oauthId);
}