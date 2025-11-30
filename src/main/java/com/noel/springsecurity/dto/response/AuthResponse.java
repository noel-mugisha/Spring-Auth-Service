package com.noel.springsecurity.dto.response;

import com.noel.springsecurity.dto.UserDto;

public record AuthResponse(
        String accessToken,
        UserDto user
) {
}
