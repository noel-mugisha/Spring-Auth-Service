package com.noel.springsecurity.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class LoweCaseValidator implements ConstraintValidator<LowerCase, String> {
    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        // If null, we let @NotNull or @NotBlank handle it.
        if (value == null) return true;
        return value.equals(value.toLowerCase());
    }
}
