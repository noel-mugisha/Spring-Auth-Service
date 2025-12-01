package com.noel.springsecurity.exceptions;

import com.noel.springsecurity.dto.response.ApiErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.JwtException;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {
    // Helper method to build response
    private ResponseEntity<ApiErrorResponse> buildResponse(HttpStatus status, String message) {
        return new ResponseEntity<>(ApiErrorResponse.builder()
                .statusCode(status.value())
                .errorReason(status.getReasonPhrase())
                .message(message)
                .build(), status);
    }

    // Handle Validation Errors (@Valid annotations)
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiErrorResponse> handleValidationErrors(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            errors.put(error.getField(), error.getDefaultMessage());
        }

        ApiErrorResponse response = ApiErrorResponse.builder()
                .statusCode(HttpStatus.BAD_REQUEST.value())
                .errorReason("Validation Failed")
                .message(errors)
                .build();

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    // Handle Token Refresh Errors (403 Forbidden)
    @ExceptionHandler(TokenRefreshException.class)
    public ResponseEntity<ApiErrorResponse> handleTokenRefreshException(TokenRefreshException ex) {
        return buildResponse(HttpStatus.FORBIDDEN, ex.getMessage());
    }

    // Handle Bad Credentials (Login fail)
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiErrorResponse> handleBadCredentials(BadCredentialsException ex) {
        return buildResponse(HttpStatus.UNAUTHORIZED, "Invalid email or password");
    }

    // Handle Disabled Account (Email not verified)
    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<ApiErrorResponse> handleDisabledAccount(DisabledException ex) {
        return buildResponse(HttpStatus.UNAUTHORIZED, "Account is disabled or email not verified");
    }

    // Handle User Already Exists
    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<ApiErrorResponse> handleUserExists(UserAlreadyExistsException ex) {
        return buildResponse(HttpStatus.CONFLICT, ex.getMessage());
    }

    // Handle Not Found
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiErrorResponse> handleNotFound(ResourceNotFoundException ex) {
        return buildResponse(HttpStatus.NOT_FOUND, ex.getMessage());
    }

    /**
     * Handling JWT Errors
     */
    // Handle Expired JWT (Crucial for Refresh Token flow)
    @ExceptionHandler(ExpiredJwtException.class)
    public ResponseEntity<ApiErrorResponse> handleExpiredJwt(ExpiredJwtException ex) {
        return buildResponse(HttpStatus.UNAUTHORIZED, "Token has expired. Please refresh your session.");
    }
    // Handle Invalid Signature / Malformed Token (Security)
    @ExceptionHandler({SignatureException.class, io.jsonwebtoken.MalformedJwtException.class, io.jsonwebtoken.security.SecurityException.class})
    public ResponseEntity<ApiErrorResponse> handleInvalidJwt(Exception ex) {
        return buildResponse(HttpStatus.UNAUTHORIZED, "Invalid authentication token.");
    }
    // Catch-all for other JWT errors
    @ExceptionHandler(JwtException.class)
    public ResponseEntity<ApiErrorResponse> handleGenericJwt(JwtException ex) {
        return buildResponse(HttpStatus.UNAUTHORIZED, "Authentication error.");
    }

    // Handle Expired Verification link toke
    @ExceptionHandler(LinkExpiredException.class)
    public ResponseEntity<ApiErrorResponse> handleExpiredVerificationLink(LinkExpiredException ex) {
        return buildResponse(HttpStatus.GONE, ex.getMessage());
    }


    // Fallback for everything else
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiErrorResponse> handleGlobalException(Exception ex) {
        log.error("Unhandled exception: {}", ex.getMessage());
        ex.printStackTrace();
        return buildResponse(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred");
    }
}