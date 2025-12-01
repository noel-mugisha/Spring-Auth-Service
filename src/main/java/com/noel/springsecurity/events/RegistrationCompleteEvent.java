package com.noel.springsecurity.events;

import com.noel.springsecurity.entities.User;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

@Getter
public class RegistrationCompleteEvent extends ApplicationEvent {
    private final User user;

    public RegistrationCompleteEvent(User user) {
        super(user);
        this.user = user;
    }
}