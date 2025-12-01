package com.noel.springsecurity.exceptions;

public class VerificationLinkExpiredException extends RuntimeException {
    public VerificationLinkExpiredException(String message) {
        super(message);
    }
}
