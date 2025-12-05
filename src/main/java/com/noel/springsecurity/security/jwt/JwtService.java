package com.noel.springsecurity.security.jwt;

import com.noel.springsecurity.entities.User;
import com.noel.springsecurity.security.UserPrincipal;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

@Service
public class JwtService {
    @Value("${app.security.jwt.secret-key}")
    private String secretKey;

    @Value("${app.security.jwt.access-token-expiration}")
    private long accessTokenExpiration;

    private static final String SCOPE_CLAIM_NAME = "scope";
    private static final String REGISTRATION_SCOPE = "PRE_AUTH_REGISTRATION";
    private static final long REGISTRATION_TOKEN_EXPIRATION = 600000; // 10 minutes (in ms)

    // Access Token
    public String generateAccessToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", user.getRole().name());
        claims.put("email", user.getEmail());

        return buildToken(claims, user.getId().toString(), accessTokenExpiration);
    }

    // Refresh Token
    public String generateRefreshToken() {
        return UUID.randomUUID().toString();
    }

    // Registration Token
    public String generateRegistrationToken(String email) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(SCOPE_CLAIM_NAME, REGISTRATION_SCOPE);
        return buildToken(claims, email, REGISTRATION_TOKEN_EXPIRATION);
    }

    // --- Helper to build tokens ---
    private String buildToken(Map<String, Object> extraClaims, String subject, long expiration) {
        return Jwts.builder()
                .claims(extraClaims)
                .subject(subject)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey())
                .compact();
    }

    // Validates Standard Access Tokens
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String tokenUserId = extractUserSubject(token);
        if (isTokenExpired(token)) {
            return false;
        }
        if (userDetails instanceof UserPrincipal userPrincipal) {
            return tokenUserId.equals(userPrincipal.getId().toString());
        }
        // Fallback: If for some reason we aren't using UserPrincipal (e.g., testing)
        return tokenUserId.equals(userDetails.getUsername());
    }

    // Validates the specific Registration Scope
    public boolean isRegistrationToken(String token) {
        try {
            if (isTokenExpired(token)) return false;
            String scope = extractClaim(token, claims -> claims.get(SCOPE_CLAIM_NAME, String.class));
            return REGISTRATION_SCOPE.equals(scope);
        } catch (Exception e) {
            return false;
        }
    }

    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // --- Extraction Logic ---
    public String extractUserSubject(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}