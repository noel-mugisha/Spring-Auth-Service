package com.noel.springsecurity.utils;

import com.noel.springsecurity.entities.User;

public interface IAuthenticationFacade {
    User getCurrentUser();
}
