package com.payments.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Utility class for JWT token operations.
 * 
 * Key features:
 * - Token generation with user claims
 * - Token validation and parsing
 * - Expiration handling
 * - Secure key management
 */
@Component
public class JwtUtil {
    
    @Value("${app.security.jwt.secret}")
    private String jwtSecret;
    
    @Value("${app.security.jwt.expiration:86400}")
    private int jwtExpirationMs;
    
    /**
     * Generates a JWT token for the given user.
     * 
     * @param userId User ID to include in the token
     * @param email User email to include in the token
     * @param firstName User first name
     * @param lastName User last name
     * @return JWT token string
     */
    public String generateToken(Long userId, String email, String firstName, String lastName) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("email", email);
        claims.put("firstName", firstName);
        claims.put("lastName", lastName);
        
        return createToken(claims, email);
    }
    
    /**
     * Creates a JWT token with the given claims and subject.
     */
    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + jwtExpirationMs * 1000L))
                .signWith(getSigningKey(), Jwts.SIG.HS256)
                .compact();
    }
    
    /**
     * Validates a JWT token.
     * 
     * @param token JWT token to validate
     * @return true if token is valid, false otherwise
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
    
    /**
     * Extracts the username (email) from a JWT token.
     * 
     * @param token JWT token
     * @return Username/email from the token
     */
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }
    
    /**
     * Extracts the user ID from a JWT token.
     * 
     * @param token JWT token
     * @return User ID from the token
     */
    public Long getUserIdFromToken(String token) {
        return getClaimFromToken(token, claims -> claims.get("userId", Long.class));
    }
    
    /**
     * Extracts a specific claim from a JWT token.
     * 
     * @param token JWT token
     * @param claimsResolver Function to extract the claim
     * @return The extracted claim
     */
    public <T> T getClaimFromToken(String token, java.util.function.Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }
    
    /**
     * Extracts all claims from a JWT token.
     * 
     * @param token JWT token
     * @return All claims from the token
     */
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
    
    /**
     * Checks if a token is expired.
     * 
     * @param token JWT token
     * @return true if token is expired, false otherwise
     */
    public Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }
    
    /**
     * Gets the expiration date from a JWT token.
     * 
     * @param token JWT token
     * @return Expiration date
     */
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }
    
    /**
     * Gets the signing key for JWT operations.
     * 
     * @return Secret key for signing/verifying tokens
     */
    private SecretKey getSigningKey() {
        byte[] keyBytes = jwtSecret.getBytes();
        return Keys.hmacShaKeyFor(keyBytes);
    }
    
    /**
     * Gets the token expiration time in seconds.
     * 
     * @return Expiration time in seconds
     */
    public int getExpirationTime() {
        return jwtExpirationMs;
    }
}
```
