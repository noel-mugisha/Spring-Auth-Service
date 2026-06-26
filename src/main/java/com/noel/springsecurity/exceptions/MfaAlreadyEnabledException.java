package com.noel.springsecurity.exceptions;

public class MfaAlreadyEnabledException extends RuntimeException {
    public MfaAlreadyEnabledException(String message) {
        super(message);
    }
}