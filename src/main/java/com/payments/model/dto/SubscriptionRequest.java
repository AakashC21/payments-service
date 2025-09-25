package com.payments.model.dto;

import jakarta.validation.constraints.*;
import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * DTO for subscription requests.
 * Contains validation for subscription creation and updates.
 */
public class SubscriptionRequest {
    
    @NotNull(message = "Amount is required")
    @DecimalMin(value = "0.01", message = "Amount must be greater than 0")
    private BigDecimal amount;
    
    @Size(max = 3, message = "Currency code must be 3 characters")
    private String currency = "USD";
    
    @NotNull(message = "Billing interval is required")
    @Min(value = 1, message = "Billing interval must be at least 1 day")
    private Integer billingIntervalDays = 30;
    
    @NotBlank(message = "Description is required")
    private String description;
    
    private String metadata;
    
    private LocalDateTime trialEndDate;
    
    // Credit card information for recurring payments
    @NotBlank(message = "Card number is required")
    private String cardNumber;
    
    @NotBlank(message = "Expiration date is required")
    @Pattern(regexp = "\\d{2}/\\d{2}", message = "Expiration date must be in MM/YY format")
    private String expirationDate;
    
    @NotBlank(message = "CVV is required")
    @Pattern(regexp = "\\d{3,4}", message = "CVV must be 3 or 4 digits")
    private String cvv;
    
    @NotBlank(message = "Cardholder name is required")
    private String cardholderName;
    
    // Billing address
    private PaymentRequest.BillingAddress billingAddress;
    
    // Constructors
    public SubscriptionRequest() {}
    
    // Getters and Setters
    public BigDecimal getAmount() { return amount; }
    public void setAmount(BigDecimal amount) { this.amount = amount; }
    
    public String getCurrency() { return currency; }
    public void setCurrency(String currency) { this.currency = currency; }
    
    public Integer getBillingIntervalDays() { return billingIntervalDays; }
    public void setBillingIntervalDays(Integer billingIntervalDays) { this.billingIntervalDays = billingIntervalDays; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public String getMetadata() { return metadata; }
    public void setMetadata(String metadata) { this.metadata = metadata; }
    
    public LocalDateTime getTrialEndDate() { return trialEndDate; }
    public void setTrialEndDate(LocalDateTime trialEndDate) { this.trialEndDate = trialEndDate; }
    
    public String getCardNumber() { return cardNumber; }
    public void setCardNumber(String cardNumber) { this.cardNumber = cardNumber; }
    
    public String getExpirationDate() { return expirationDate; }
    public void setExpirationDate(String expirationDate) { this.expirationDate = expirationDate; }
    
    public String getCvv() { return cvv; }
    public void setCvv(String cvv) { this.cvv = cvv; }
    
    public String getCardholderName() { return cardholderName; }
    public void setCardholderName(String cardholderName) { this.cardholderName = cardholderName; }
    
    public PaymentRequest.BillingAddress getBillingAddress() { return billingAddress; }
    public void setBillingAddress(PaymentRequest.BillingAddress billingAddress) { this.billingAddress = billingAddress; }
}
```

```java:src/main/java/com/payments/model/dto/SubscriptionResponse.java
package com.payments.model.dto;

import com.payments.model.entity.Subscription;
import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * DTO for subscription responses.
 * Contains all relevant subscription information for the client.
 */
public class SubscriptionResponse {
    
    private Long id;
    private BigDecimal amount;
    private String currency;
    private Subscription.SubscriptionStatus status;
    private String subscriptionId;
    private LocalDateTime nextBillingDate;
    private Integer billingIntervalDays;
    private String description;
    private String metadata;
    private LocalDateTime trialEndDate;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    
    // Constructors
    public SubscriptionResponse() {}
    
    public SubscriptionResponse(Long id, BigDecimal amount, String currency, 
                               Subscription.SubscriptionStatus status, String subscriptionId) {
        this.id = id;
        this.amount = amount;
        this.currency = currency;
        this.status = status;
        this.subscriptionId = subscriptionId;
    }
    
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public BigDecimal getAmount() { return amount; }
    public void setAmount(BigDecimal amount) { this.amount = amount; }
    
    public String getCurrency() { return currency; }
    public void setCurrency(String currency) { this.currency = currency; }
    
    public Subscription.SubscriptionStatus getStatus() { return status; }
    public void setStatus(Subscription.SubscriptionStatus status) { this.status = status; }
    
    public String getSubscriptionId() { return subscriptionId; }
    public void setSubscriptionId(String subscriptionId) { this.subscriptionId = subscriptionId; }
    
    public LocalDateTime getNextBillingDate() { return nextBillingDate; }
    public void setNextBillingDate(LocalDateTime nextBillingDate) { this.nextBillingDate = nextBillingDate; }
    
    public Integer getBillingIntervalDays() { return billingIntervalDays; }
    public void setBillingIntervalDays(Integer billingIntervalDays) { this.billingIntervalDays = billingIntervalDays; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public String getMetadata() { return metadata; }
    public void setMetadata(String metadata) { this.metadata = metadata; }
    
    public LocalDateTime getTrialEndDate() { return trialEndDate; }
    public void setTrialEndDate(LocalDateTime trialEndDate) { this.trialEndDate = trialEndDate; }
    
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    
    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }
}
```

```java:src/main/java/com/payments/model/dto/ErrorResponse.java
package com.payments.model.dto;

import java.time.LocalDateTime;
import java.util.List;

/**
 * DTO for standardized error responses.
 * Provides consistent error format across the API.
 */
public class ErrorResponse {
    
    private String code;
    private String message;
    private List<String> details;
    private LocalDateTime timestamp;
    private String correlationId;
    
    // Constructors
    public ErrorResponse() {
        this.timestamp = LocalDateTime.now();
    }
    
    public ErrorResponse(String code, String message) {
        this();
        this.code = code;
        this.message = message;
    }
    
    public ErrorResponse(String code, String message, List<String> details) {
        this(code, message);
        this.details = details;
    }
    
    // Getters and Setters
    public String getCode() { return code; }
    public void setCode(String code) { this.code = code; }
    
    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
    
    public List<String> getDetails() { return details; }
    public void setDetails(List<String> details) { this.details = details; }
    
    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
    
    public String getCorrelationId() { return correlationId; }
    public void setCorrelationId(String correlationId) { this.correlationId = correlationId; }
}
```

```java:src/main/java/com/payments/model/dto/ApiResponse.java
package com.payments.model.dto;

/**
 * Generic DTO for API responses.
 * Provides consistent response format with success/error indication.
 */
public class ApiResponse<T> {
    
    private boolean success;
    private String message;
    private T data;
    private String correlationId;
    
    // Constructors
    public ApiResponse() {}
    
    public ApiResponse(boolean success, String message, T data) {
        this.success = success;
        this.message = message;
        this.data = data;
    }
    
    // Static factory methods
    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>(true, "Success", data);
    }
    
    public static <T> ApiResponse<T> success(String message, T data) {
        return new ApiResponse<>(true, message, data);
    }
    
    public static <T> ApiResponse<T> error(String message) {
        return new ApiResponse<>(false, message, null);
    }
    
    // Getters and Setters
    public boolean isSuccess() { return success; }
    public void setSuccess(boolean success) { this.success = success; }
    
    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
    
    public T getData() { return data; }
    public void setData(T data) { this.data = data; }
    
    public String getCorrelationId() { return correlationId; }
    public void setCorrelationId(String correlationId) { this.correlationId = correlationId; }
}
```

```java:src/main/java/com/payments/util/JwtUtil.java
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

```java:src/main/java/com/payments/util/CorrelationIdUtil.java
package com.payments.util;

import org.slf4j.MDC;

import java.util.UUID;

/**
 * Utility class for correlation ID management.
 * 
 * Key features:
 * - Generates unique correlation IDs
 * - Manages correlation ID in MDC for logging
 * - Thread-safe correlation ID handling
 */
public class CorrelationIdUtil {
    
    private static final String CORRELATION_ID_KEY = "correlationId";
    
    /**
     * Generates a new correlation ID.
     * 
     * @return New correlation ID string
     */
    public static String generateCorrelationId() {
        return UUID.randomUUID().toString();
    }
    
    /**
     * Sets the correlation ID in the current thread's MDC.
     * 
     * @param correlationId Correlation ID to set
     */
    public static void setCorrelationId(String correlationId) {
        if (correlationId != null && !correlationId.isEmpty()) {
            MDC.put(CORRELATION_ID_KEY, correlationId);
        }
    }
    
    /**
     * Gets the correlation ID from the current thread's MDC.
     * 
     * @return Current correlation ID or null if not set
     */
    public static String getCorrelationId() {
        return MDC.get(CORRELATION_ID_KEY);
    }
    
    /**
     * Clears the correlation ID from the current thread's MDC.
     */
    public static void clearCorrelationId() {
        MDC.remove(CORRELATION_ID_KEY);
    }
    
    /**
     * Gets the correlation ID or generates a new one if not present.
     * 
     * @return Current or new correlation ID
     */
    public static String getOrGenerateCorrelationId() {
        String correlationId = getCorrelationId();
        if (correlationId == null || correlationId.isEmpty()) {
            correlationId = generateCorrelationId();
            setCorrelationId(correlationId);
        }
        return correlationId;
    }
}
```

```java:src/main/java/com/payments/middleware/CorrelationIdFilter.java
package com.payments.middleware;

import com.payments.util.CorrelationIdUtil;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Filter to handle correlation ID propagation across requests.
 * 
 * Key features:
 * - Extracts correlation ID from request headers
 * - Generates new correlation ID if not present
 * - Sets correlation ID in MDC for logging
 * - Adds correlation ID to response headers
 * - Ensures correlation ID is available throughout request processing
 */
@Component
@Order(1)
public class CorrelationIdFilter implements Filter {
    
    private static final String CORRELATION_ID_HEADER = "X-Correlation-ID";
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        
        try {
            // Extract correlation ID from request header or generate new one
            String correlationId = httpRequest.getHeader(CORRELATION_ID_HEADER);
            if (correlationId == null || correlationId.isEmpty()) {
                correlationId = CorrelationIdUtil.generateCorrelationId();
            }
            
            // Set correlation ID in MDC for logging
            CorrelationIdUtil.setCorrelationId(correlationId);
            
            // Add correlation ID to response headers
            httpResponse.setHeader(CORRELATION_ID_HEADER, correlationId);
            
            // Continue with the filter chain
            chain.doFilter(request, response);
            
        } finally {
            // Clean up correlation ID from MDC after request processing
            CorrelationIdUtil.clearCorrelationId();
        }
    }
}
```

```java:src/main/java/com/payments/middleware/JwtAuthenticationFilter.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    
    public JwtAuthenticationFilter(String jwtSecret) {
        this.jwtUtil = new JwtUtil();
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_USER"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/RequestLoggingInterceptor.java
package com.payments.middleware;

import com.payments.util.CorrelationIdUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

/**
 * Interceptor for logging HTTP requests and responses.
 * 
 * Key features:
 * - Logs request details (method, URI, headers)
 * - Logs response status and timing
 * - Includes correlation ID in all log entries
 * - Excludes sensitive data from logs
 */
@Component
public class RequestLoggingInterceptor implements HandlerInterceptor {
    
    private static final Logger logger = LoggerFactory.getLogger(RequestLoggingInterceptor.class);
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        long startTime = System.currentTimeMillis();
        request.setAttribute("startTime", startTime);
        
        String correlationId = CorrelationIdUtil.getCorrelationId();
        
        // Log request details
        Map<String, Object> requestLog = new HashMap<>();
        requestLog.put("correlationId", correlationId);
        requestLog.put("method", request.getMethod());
        requestLog.put("uri", request.getRequestURI());
        requestLog.put("queryString", request.getQueryString());
        requestLog.put("remoteAddr", getClientIpAddress(request));
        
        // Log headers (excluding sensitive ones)
        Map<String, String> headers = new HashMap<>();
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            if (!isSensitiveHeader(headerName)) {
                headers.put(headerName, request.getHeader(headerName));
            }
        }
        requestLog.put("headers", headers);
        
        logger.info("Request received: {}", requestLog);
        
        return true;
    }
    
    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, 
                               Object handler, Exception ex) throws Exception {
        
        long startTime = (Long) request.getAttribute("startTime");
        long endTime = System.currentTimeMillis();
        long executionTime = endTime - startTime;
        
        String correlationId = CorrelationIdUtil.getCorrelationId();
        
        // Log response details
        Map<String, Object> responseLog = new HashMap<>();
        responseLog.put("correlationId", correlationId);
        responseLog.put("status", response.getStatus());
        responseLog.put("executionTime", executionTime + "ms");
        
        if (ex != null) {
            responseLog.put("error", ex.getMessage());
        }
        
        logger.info("Request completed: {}", responseLog);
    }
    
    /**
     * Gets the client IP address from the request.
     * Handles proxy headers like X-Forwarded-For.
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }
    
    /**
     * Checks if a header contains sensitive information.
     * 
     * @param headerName Header name to check
     * @return true if header is sensitive and should not be logged
     */
    private boolean isSensitiveHeader(String headerName) {
        String lowerHeaderName = headerName.toLowerCase();
        return lowerHeaderName.contains("authorization") ||
               lowerHeaderName.contains("cookie") ||
               lowerHeaderName.contains("x-api-key") ||
               lowerHeaderName.contains("password");
    }
}
```

```java:src/main/java/com/payments/middleware/GlobalExceptionHandler.java
package com.payments.middleware;

import com.payments.model.dto.ApiResponse;
import com.payments.model.dto.ErrorResponse;
import com.payments.util.CorrelationIdUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.util.ArrayList;
import java.util.List;

/**
 * Global exception handler for consistent error responses.
 * 
 * Key features:
 * - Centralized exception handling
 * - Consistent error response format
 * - Correlation ID inclusion in error responses
 * - Proper HTTP status code mapping
 * - Detailed logging for debugging
 */
@RestControllerAdvice
public class GlobalExceptionHandler {
    
    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    
    /**
     * Handles validation errors from @Valid annotations.
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleValidationExceptions(
            MethodArgumentNotValidException ex, WebRequest request) {
        
        List<String> details = new ArrayList<>();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            details.add(error.getDefaultMessage());
        }
        
        ErrorResponse errorResponse = new ErrorResponse(
                "VALIDATION_ERROR",
                "Validation failed",
                details
        );
        
        return new ResponseEntity<>(
                new ApiResponse<>(false, "Validation failed", errorResponse),
                HttpStatus.BAD_REQUEST
        );
    }
    
    /**
     * Handles authentication exceptions (e.g., BadCredentialsException, AuthenticationException).
     */
    @ExceptionHandler({BadCredentialsException.class, AuthenticationException.class})
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAuthenticationExceptions(
            Exception ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "AUTHENTICATION_ERROR",
                "Authentication failed",
                List.of(ex.getMessage())
        );
        
        return new ResponseEntity<>(
                new ApiResponse<>(false, "Authentication failed", errorResponse),
                HttpStatus.UNAUTHORIZED
        );
    }
    
    /**
     * Handles access denied exceptions (e.g., AccessDeniedException).
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAccessDeniedExceptions(
            Exception ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "ACCESS_DENIED",
                "Access denied",
                List.of(ex.getMessage())
        );
        
        return new ResponseEntity<>(
                new ApiResponse<>(false, "Access denied", errorResponse),
                HttpStatus.FORBIDDEN
        );
    }
    
    /**
     * Handles general application exceptions.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleGlobalExceptions(
            Exception ex, WebRequest request) {
        
        logger.error("Unhandled exception: {}", ex.getMessage(), ex);
        
        ErrorResponse errorResponse = new ErrorResponse(
                "INTERNAL_SERVER_ERROR",
                "An unexpected error occurred",
                List.of(ex.getMessage())
        );
        
        return new ResponseEntity<>(
                new ApiResponse<>(false, "Internal server error", errorResponse),
                HttpStatus.INTERNAL_SERVER_ERROR
        );
    }
    
    /**
     * Handles specific business exceptions.
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleBusinessExceptions(
            RuntimeException ex, WebRequest request) {
        
        logger.error("Business exception: {}", ex.getMessage(), ex);
        
        ErrorResponse errorResponse = new ErrorResponse(
                "BUSINESS_ERROR",
                ex.getMessage()
        );
        
        return new ResponseEntity<>(
                new ApiResponse<>(false, "Business error", errorResponse),
                HttpStatus.BAD_REQUEST
        );
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookEventInterceptor.java
package com.payments.middleware;

import com.payments.model.entity.WebhookEvent;
import com.payments.util.CorrelationIdUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

/**
 * Interceptor for logging webhook events.
 * 
 * Key features:
 * - Logs webhook event details (payload, signature, status)
 * - Includes correlation ID in all log entries
 * - Excludes sensitive data from logs
 */
@Component
public class WebhookEventInterceptor implements HandlerInterceptor {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookEventInterceptor.class);
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        long startTime = System.currentTimeMillis();
        request.setAttribute("startTime", startTime);
        
        String correlationId = CorrelationIdUtil.getCorrelationId();
        
        // Log webhook event details
        Map<String, Object> webhookLog = new HashMap<>();
        webhookLog.put("correlationId", correlationId);
        webhookLog.put("eventType", request.getHeader("X-Event-Type"));
        webhookLog.put("eventId", request.getHeader("X-Event-ID"));
        webhookLog.put("signature", request.getHeader("X-Signature"));
        
        // Log payload (excluding sensitive data)
        try {
            Map<String, Object> payload = objectMapper.readValue(request.getInputStream(), Map.class);
            // Exclude sensitive fields like signature, card number, CVV
            payload.remove("signature");
            payload.remove("cardNumber");
            payload.remove("cvv");
            payload.remove("password");
            webhookLog.put("payload", payload);
        } catch (Exception e) {
            webhookLog.put("payload", "Could not parse payload");
        }
        
        logger.info("Webhook event received: {}", webhookLog);
        
        return true;
    }
    
    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, 
                               Object handler, Exception ex) throws Exception {
        
        long startTime = (Long) request.getAttribute("startTime");
        long endTime = System.currentTimeMillis();
        long executionTime = endTime - startTime;
        
        String correlationId = CorrelationIdUtil.getCorrelationId();
        
        // Log webhook event completion
        Map<String, Object> webhookLog = new HashMap<>();
        webhookLog.put("correlationId", correlationId);
        webhookLog.put("eventType", request.getHeader("X-Event-Type"));
        webhookLog.put("eventId", request.getHeader("X-Event-ID"));
        webhookLog.put("status", response.getStatus());
        webhookLog.put("executionTime", executionTime + "ms");
        
        if (ex != null) {
            webhookLog.put("error", ex.getMessage());
        }
        
        logger.info("Webhook event completed: {}", webhookLog);
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
```

```java:src/main/java/com/payments/middleware/WebhookSignatureInterceptor.java
package com.payments.middleware;

import com.payments.util.JwtUtil;
import com.payments.util.WebhookUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter for securing API endpoints.
 * 
 * Key features:
 * - Extracts JWT token from Authorization header
 * - Validates token and sets authentication context
 * - Handles various JWT exceptions gracefully
 * - Integrates with Spring Security
 */
@Component
public class WebhookSignatureInterceptor extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookSignatureInterceptor.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    private final WebhookUtil webhookUtil;
    
    public WebhookSignatureInterceptor(String jwtSecret, String webhookSecret) {
        this.jwtUtil = new JwtUtil();
        this.webhookUtil = new WebhookUtil(webhookSecret);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = parseJwt(request);
            
            if (jwt != null && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                Long userId = jwtUtil.getUserIdFromToken(jwt);
                
                // Create authentication token
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        List.of(new SimpleGrantedAuthority("ROLE_WEBHOOK"))
                    );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                // Add user ID to request attributes for easy access in controllers
                request.setAttribute("userId", userId);
                request.setAttribute("username", username);
            }
            
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from the Authorization header.
     * 
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        
        if (headerAuth != null && headerAuth.startsWith
