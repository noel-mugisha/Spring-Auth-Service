package com.noel.springsecurity.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class PasswordValidator implements ConstraintValidator<Password, String> {

    private static final Pattern HAS_DIGIT = Pattern.compile(".*\\d.*");
    private static final Pattern HAS_UPPERCASE = Pattern.compile(".*[A-Z].*");
    private static final Pattern HAS_SPECIAL_CHAR = Pattern.compile(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*");
    private static final int MIN_LENGTH = 8;

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        if (password == null) return true; // Let @NotBlank handle nulls

        List<String> violations = new ArrayList<>();

        if (password.length() < MIN_LENGTH) {
            violations.add("must be at least " + MIN_LENGTH + " characters long");
        }
        if (!HAS_DIGIT.matcher(password).matches()) {
            violations.add("must contain at least one number");
        }
        if (!HAS_UPPERCASE.matcher(password).matches()) {
            violations.add("must contain at least one uppercase letter");
        }
        if (!HAS_SPECIAL_CHAR.matcher(password).matches()) {
            violations.add("must contain at least one special character");
        }

        if (violations.isEmpty()) {
            return true;
        }

        // Build a helpful error message for the frontend
        String message = "Password " + String.join(", ", violations);

        context.disableDefaultConstraintViolation();
        context.buildConstraintViolationWithTemplate(message)
                .addConstraintViolation();

        return false;
    }
}
