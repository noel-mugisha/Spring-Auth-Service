package com.noel.springsecurity.dto;

import java.util.UUID;

public record UserDto(
        UUID id,
        String fullName,
        String email,
        String role
) {
}
