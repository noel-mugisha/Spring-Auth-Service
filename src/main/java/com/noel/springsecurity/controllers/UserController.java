package com.noel.springsecurity.controllers;

import com.noel.springsecurity.dto.UserDto;
import com.noel.springsecurity.services.IUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final IUserService userService;

    @GetMapping("/me")
    public ResponseEntity<UserDto> getCurrentUser() {
        UserDto userProfile = userService.getCurrentUserProfile();
        return ResponseEntity.ok(userProfile);
    }
}