package com.noel.springsecurity.repositories;

import com.noel.springsecurity.entities.MfaRecoveryCode;
import com.noel.springsecurity.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface IMfaRecoveryCodeRepository extends JpaRepository<MfaRecoveryCode, UUID> {

    Optional<MfaRecoveryCode> findByUserAndCodeHash(User user, String codeHash);

    void deleteByUser(User user);
}