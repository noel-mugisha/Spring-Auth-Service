package com.noel.springsecurity.events;

import com.noel.springsecurity.entities.User;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

@Getter
public class PasswordResetRequestedEvent extends ApplicationEvent {
    private final User user;
    private final String rawToken;

    public PasswordResetRequestedEvent(User user, String rawToken) {
        super(user);
        this.user = user;
        this.rawToken = rawToken;
    }
}