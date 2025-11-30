package com.noel.springsecurity.repositories;

import com.noel.springsecurity.entities.RefreshToken;
import com.noel.springsecurity.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {
    // Validation: Find the token by the hash we generated from the cookie
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    // Rotation/Logout: Delete the specific token chain
    void deleteByTokenHash(String tokenHash);

    // Logout all devices: Delete all tokens for a specific user
    void deleteByUser(User user);
}
