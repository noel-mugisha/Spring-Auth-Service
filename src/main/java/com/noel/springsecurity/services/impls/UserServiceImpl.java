package com.noel.springsecurity.services.impls;

import com.noel.springsecurity.dto.UserDto;
import com.noel.springsecurity.entities.User;
import com.noel.springsecurity.mappers.IUserMapper;
import com.noel.springsecurity.services.IUserService;
import com.noel.springsecurity.utils.IAuthenticationFacade;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements IUserService {

    private final IAuthenticationFacade authenticationFacade;
    private final IUserMapper userMapper;

    @Override
    @Transactional(readOnly = true)
    public UserDto getCurrentUserProfile() {
        User currentUser = authenticationFacade.getCurrentUser();
        return userMapper.toDto(currentUser);
    }
}