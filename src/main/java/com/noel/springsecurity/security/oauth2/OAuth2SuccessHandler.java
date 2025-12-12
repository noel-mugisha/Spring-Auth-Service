package com.noel.springsecurity.security.oauth2;

import com.noel.springsecurity.entities.User;
import com.noel.springsecurity.security.UserPrincipal;
import com.noel.springsecurity.services.IRefreshTokenService;
import com.noel.springsecurity.utils.CookieUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.util.Optional;

import static com.noel.springsecurity.security.oauth2.HttpCookieOAuth2AuthorizationRequestRepository.OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME;
import static com.noel.springsecurity.security.oauth2.HttpCookieOAuth2AuthorizationRequestRepository.REDIRECT_URI_PARAM_COOKIE_NAME;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final IRefreshTokenService refreshTokenService;
    private final CookieUtil cookieUtil;
    @Value("${app.security.oauth2.redirect-uri}")
    private String defaultFrontendRedirectUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        UserPrincipal principal = (UserPrincipal) authentication.getPrincipal();
        User user = principal.getUser();
        String rawRefreshToken = refreshTokenService.createRefreshToken(user);
        response.addHeader("Set-Cookie", cookieUtil.createRefreshTokenCookie(rawRefreshToken).toString());
        // Determine Target URL (Deep Linking Logic)
        String targetUrl = determineTargetUrl(request, response, authentication);
        // Clear temporary OAuth2 cookies
        clearAuthenticationAttributes(request, response);
        // Redirect to frontend
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        Optional<String> redirectUri = cookieUtil.getCookie(request, REDIRECT_URI_PARAM_COOKIE_NAME)
                .map(Cookie::getValue);
        if (redirectUri.isPresent() && !isAuthorizedRedirectUri(redirectUri.get())) {
            log.warn("Unauthorized redirect URI detected: {}. Falling back to default.", redirectUri.get());
            return defaultFrontendRedirectUrl;
        }
        return redirectUri.orElse(defaultFrontendRedirectUrl);
    }

    /**
     * Security Check: Prevent Open Redirect Attacks.
     * We only allow redirects that match the Host and Port of our configured Frontend.
     */
    private boolean isAuthorizedRedirectUri(String uri) {
        URI clientRedirectUri = URI.create(uri);
        URI authorizedUri = URI.create(defaultFrontendRedirectUrl);

        return authorizedUri.getHost().equalsIgnoreCase(clientRedirectUri.getHost())
                && authorizedUri.getPort() == clientRedirectUri.getPort();
    }

    private void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        cookieUtil.deleteCookie(request, response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME);
        cookieUtil.deleteCookie(request, response, REDIRECT_URI_PARAM_COOKIE_NAME);
    }
}