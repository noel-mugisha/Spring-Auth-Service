package com.noel.springsecurity.utils;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseCookie;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.Serializable;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class CookieUtilTest {

    private CookieUtil cookieUtil;

    @BeforeEach
    void setUp() {
        cookieUtil = new CookieUtil();
        ReflectionTestUtils.setField(cookieUtil, "refreshTokenExpiration", 604_800_000L); // 7 days, ms
    }

    @Test
    void createRefreshTokenCookie_isHttpOnlySecureAndScopedToTheWholeSite() {
        ResponseCookie cookie = cookieUtil.createRefreshTokenCookie("a-refresh-token");

        assertThat(cookie.getName()).isEqualTo("refresh_token");
        assertThat(cookie.getValue()).isEqualTo("a-refresh-token");
        assertThat(cookie.isHttpOnly()).isTrue();
        assertThat(cookie.isSecure()).isTrue();
        assertThat(cookie.getPath()).isEqualTo("/");
        assertThat(cookie.getSameSite()).isEqualTo("Strict");
        assertThat(cookie.getMaxAge().getSeconds()).isEqualTo(604_800L);
    }

    @Test
    void getCleanRefreshTokenCookie_clearsTheValueAndExpiresImmediately() {
        ResponseCookie cookie = cookieUtil.getCleanRefreshTokenCookie();

        assertThat(cookie.getValue()).isEmpty();
        assertThat(cookie.getMaxAge().getSeconds()).isZero();
    }

    @Test
    void getCookie_findsACookieByNameWhenPresent() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("oauth2_state", "xyz"));

        Optional<Cookie> found = cookieUtil.getCookie(request, "oauth2_state");

        assertThat(found).isPresent();
        assertThat(found.get().getValue()).isEqualTo("xyz");
    }

    @Test
    void getCookie_returnsEmptyWhenNoCookiesExist() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        assertThat(cookieUtil.getCookie(request, "anything")).isEmpty();
    }

    @Test
    void addCookie_writesAnHttpOnlyCookieToTheResponse() {
        MockHttpServletResponse response = new MockHttpServletResponse();

        cookieUtil.addCookie(response, "session_hint", "abc", 3600);

        Cookie added = response.getCookie("session_hint");
        assertThat(added).isNotNull();
        assertThat(added.getValue()).isEqualTo("abc");
        assertThat(added.isHttpOnly()).isTrue();
        assertThat(added.getMaxAge()).isEqualTo(3600);
    }

    @Test
    void deleteCookie_overwritesTheCookieWithAnImmediatelyExpiringEmptyOne() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("oauth2_state", "xyz"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        cookieUtil.deleteCookie(request, response, "oauth2_state");

        Cookie deleted = response.getCookie("oauth2_state");
        assertThat(deleted).isNotNull();
        assertThat(deleted.getValue()).isEmpty();
        assertThat(deleted.getMaxAge()).isZero();
    }

    @Test
    void serializeThenDeserialize_roundTripsAnObjectExactly() {
        DummyState original = new DummyState("redirect-uri", 42);

        String serialized = cookieUtil.serialize(original);
        Cookie cookie = new Cookie("state", serialized);
        DummyState restored = cookieUtil.deserialize(cookie, DummyState.class);

        assertThat(restored.value()).isEqualTo("redirect-uri");
        assertThat(restored.count()).isEqualTo(42);
    }

    // A minimal stand-in for the real OAuth2AuthorizationRequest this is used for in production.
    private record DummyState(String value, int count) implements Serializable {}
}