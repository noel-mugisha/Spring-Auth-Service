package com.noel.springsecurity.validation;

import jakarta.validation.ConstraintValidatorContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PasswordValidatorTest {

    private final PasswordValidator validator = new PasswordValidator();

    @Mock private ConstraintValidatorContext context;
    @Mock private ConstraintValidatorContext.ConstraintViolationBuilder violationBuilder;

    @Test
    void isValid_acceptsNull_becauseNotBlankHandlesThatCase() {
        assertThat(validator.isValid(null, context)).isTrue();
    }

    @Test
    void isValid_acceptsAStrongPassword() {
        assertThat(validator.isValid("Str0ng!Pass", context)).isTrue();
    }

    @Test
    void isValid_rejectsAPasswordThatIsTooShort() {
        stubViolationBuilder();
        assertThat(validator.isValid("Ab1!", context)).isFalse();
    }

    @Test
    void isValid_rejectsAPasswordWithNoDigit() {
        stubViolationBuilder();
        assertThat(validator.isValid("NoDigitsHere!", context)).isFalse();
    }

    @Test
    void isValid_rejectsAPasswordWithNoUppercase() {
        stubViolationBuilder();
        assertThat(validator.isValid("nouppercase1!", context)).isFalse();
    }

    @Test
    void isValid_rejectsAPasswordWithNoSpecialCharacter() {
        stubViolationBuilder();
        assertThat(validator.isValid("NoSpecial123", context)).isFalse();
    }

    @Test
    void isValid_buildsACustomMessageListingEveryViolation() {
        stubViolationBuilder();

        validator.isValid("short", context); // fails length, digit, uppercase, AND special char

        verify(context).disableDefaultConstraintViolation();
        verify(context).buildConstraintViolationWithTemplate(
                "Password must be at least 8 characters long, must contain at least one number, " +
                        "must contain at least one uppercase letter, must contain at least one special character"
        );
    }

    private void stubViolationBuilder() {
        when(context.buildConstraintViolationWithTemplate(any())).thenReturn(violationBuilder);
    }
}