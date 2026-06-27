package com.noel.springsecurity.utils;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TokenHashUtilTest {

    @Test
    void hashToken_isDeterministic_sameInputAlwaysProducesSameHash() {
        assertThat(TokenHashUtil.hashToken("my-raw-token"))
                .isEqualTo(TokenHashUtil.hashToken("my-raw-token"));
    }

    @Test
    void hashToken_differentInputsProduceDifferentHashes() {
        assertThat(TokenHashUtil.hashToken("token-a"))
                .isNotEqualTo(TokenHashUtil.hashToken("token-b"));
    }

    @Test
    void hashToken_neverReturnsThePlaintextToken() {
        String raw = "super-secret-refresh-token";
        assertThat(TokenHashUtil.hashToken(raw)).isNotEqualTo(raw);
    }

    @Test
    void hashToken_producesAStandardSha256Length() {
        // SHA-256 -> 32 raw bytes -> 44 Base64 characters (with padding)
        assertThat(TokenHashUtil.hashToken("anything")).hasSize(44);
    }
}