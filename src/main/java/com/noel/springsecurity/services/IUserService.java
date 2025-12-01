package com.noel.springsecurity.services;

import com.noel.springsecurity.dto.UserDto;

public interface IUserService {

    UserDto getCurrentUserProfile();
}