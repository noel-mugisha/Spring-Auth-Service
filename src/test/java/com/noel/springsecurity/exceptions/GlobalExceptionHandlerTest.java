package com.noel.springsecurity.exceptions;

import com.noel.springsecurity.dto.response.ApiErrorResponse;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    void handleValidationErrors_collectsEveryFieldIntoAMap() {
        BindingResult bindingResult = mock(BindingResult.class);
        when(bindingResult.getFieldErrors()).thenReturn(List.of(
                new FieldError("loginRequest", "email", "Email is required"),
                new FieldError("loginRequest", "password", "Password is required")
        ));
        MethodArgumentNotValidException ex = mock(MethodArgumentNotValidException.class);
        when(ex.getBindingResult()).thenReturn(bindingResult);

        ResponseEntity<ApiErrorResponse> response = handler.handleValidationErrors(ex);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        @SuppressWarnings("unchecked")
        Map<String, String> errors = (Map<String, String>) response.getBody().getMessage();
        assertThat(errors).containsEntry("email", "Email is required");
        assertThat(errors).containsEntry("password", "Password is required");
    }

    @Test
    void handleBadCredentials_mapsTo401WithTheExceptionMessage() {
        ResponseEntity<ApiErrorResponse> response =
                handler.handleBadCredentials(new BadCredentialsException("Invalid email or password"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody().getMessage()).isEqualTo("Invalid email or password");
    }

    @Test
    void handleMfaAlreadyEnabled_mapsTo409Conflict() {
        ResponseEntity<ApiErrorResponse> response =
                handler.handleMfaAlreadyEnabled(new MfaAlreadyEnabledException("MFA is already enabled."));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    }
}