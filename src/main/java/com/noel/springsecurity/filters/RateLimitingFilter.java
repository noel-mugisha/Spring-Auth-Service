package com.noel.springsecurity.filters;

import com.noel.springsecurity.exceptions.RateLimitExceededException;
import com.noel.springsecurity.services.RateLimitingService;
import io.github.bucket4j.Bucket;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class RateLimitingFilter extends OncePerRequestFilter {

    private final RateLimitingService rateLimitingService;
    private final HandlerExceptionResolver handlerExceptionResolver;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        // Only apply to Auth endpoints
        if (request.getRequestURI().startsWith("/api/v1/auth")) {
            // Identify the Client (IP Address)
            String clientIp = getClientIp(request);
            // Get their bucket
            Bucket bucket = rateLimitingService.resolveBucket(clientIp);
            // Try to consume 1 token
            if (bucket.tryConsume(1)) {
                // Success: Proceed
                filterChain.doFilter(request, response);
            } else {
                // Failure: Throw Exception (caught by GlobalExceptionHandler)
                handlerExceptionResolver.resolveException(request, response, null,
                        new RateLimitExceededException("Too many requests. Please try again later."));
            }
        } else {
            // Not an auth route? Just continue.
            filterChain.doFilter(request, response);
        }
    }

    /**
     * Extracts the real IP address, handling proxies/load balancers.
     */
    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        // X-Forwarded-For: client, proxy1, proxy2
        return xfHeader.split(",")[0];
    }
}