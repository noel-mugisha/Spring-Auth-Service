package com.noel.springsecurity.mappers;

import com.noel.springsecurity.dto.UserDto;
import com.noel.springsecurity.entities.User;
import org.mapstruct.Mapper;
import org.mapstruct.NullValuePropertyMappingStrategy;

@Mapper(
        componentModel = "spring",
        nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE
)
public interface IUserMapper {
    UserDto toDto(User user);
}
