package com.noel.springsecurity.validation;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LoweCaseValidatorTest {

    private final LoweCaseValidator validator = new LoweCaseValidator();

    @Test
    void isValid_acceptsNull_becauseNotBlankHandlesThatCase() {
        assertThat(validator.isValid(null, null)).isTrue();
    }

    @Test
    void isValid_acceptsAnAlreadyLowercaseString() {
        assertThat(validator.isValid("jane@example.com", null)).isTrue();
    }

    @Test
    void isValid_rejectsAnyUppercaseCharacter() {
        assertThat(validator.isValid("Jane@example.com", null)).isFalse();
    }
}