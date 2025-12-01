package com.noel.springsecurity.services;

import com.noel.springsecurity.dto.UserDto;

import java.util.List;

public interface IUserService {

    UserDto getCurrentUserProfile();

    List<UserDto> getAllUsers();
}