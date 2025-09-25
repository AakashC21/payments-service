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
            details.add(error.getField() + ": " + error.getDefaultMessage());
        }
        
        ErrorResponse errorResponse = new ErrorResponse(
                "VALIDATION_ERROR",
                "Validation failed",
                details
        );
        
        logger.error("Validation error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.BAD_REQUEST);
    }
    
    /**
     * Handles authentication exceptions.
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAuthenticationExceptions(
            AuthenticationException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "AUTHENTICATION_ERROR",
                "Authentication failed",
                List.of(ex.getMessage())
        );
        
        logger.error("Authentication error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.UNAUTHORIZED);
    }
    
    /**
     * Handles authorization exceptions.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAuthorizationExceptions(
            AccessDeniedException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "AUTHORIZATION_ERROR",
                "Access denied",
                List.of(ex.getMessage())
        );
        
        logger.error("Authorization error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.FORBIDDEN);
    }
    
    /**
     * Handles BadCredentialsException.
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleBadCredentialsException(
            BadCredentialsException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "BAD_CREDENTIALS_ERROR",
                "Invalid credentials",
                List.of("Invalid username or password")
        );
        
        logger.error("Bad credentials error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.UNAUTHORIZED);
    }
    
    /**
     * Handles general exceptions.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleGlobalExceptions(
            Exception ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "INTERNAL_SERVER_ERROR",
                "An unexpected error occurred",
                List.of(ex.getMessage())
        );
        
        logger.error("Global error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
    }
    
    /**
     * Handles specific business exceptions.
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleBusinessExceptions(
            RuntimeException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "BUSINESS_ERROR",
                "A business error occurred",
                List.of(ex.getMessage())
        );
        
        logger.error("Business error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.BAD_REQUEST);
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
            details.add(error.getField() + ": " + error.getDefaultMessage());
        }
        
        ErrorResponse errorResponse = new ErrorResponse(
                "VALIDATION_ERROR",
                "Validation failed",
                details
        );
        
        logger.error("Validation error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.BAD_REQUEST);
    }
    
    /**
     * Handles authentication exceptions.
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAuthenticationExceptions(
            AuthenticationException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "AUTHENTICATION_ERROR",
                "Authentication failed",
                List.of(ex.getMessage())
        );
        
        logger.error("Authentication error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.UNAUTHORIZED);
    }
    
    /**
     * Handles authorization exceptions.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAuthorizationExceptions(
            AccessDeniedException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "AUTHORIZATION_ERROR",
                "Access denied",
                List.of(ex.getMessage())
        );
        
        logger.error("Authorization error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.FORBIDDEN);
    }
    
    /**
     * Handles BadCredentialsException.
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleBadCredentialsException(
            BadCredentialsException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "BAD_CREDENTIALS_ERROR",
                "Invalid credentials",
                List.of("Invalid username or password")
        );
        
        logger.error("Bad credentials error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.UNAUTHORIZED);
    }
    
    /**
     * Handles general exceptions.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleGlobalExceptions(
            Exception ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "INTERNAL_SERVER_ERROR",
                "An unexpected error occurred",
                List.of(ex.getMessage())
        );
        
        logger.error("Global error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
    }
    
    /**
     * Handles specific business exceptions.
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleBusinessExceptions(
            RuntimeException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "BUSINESS_ERROR",
                "A business error occurred",
                List.of(ex.getMessage())
        );
        
        logger.error("Business error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.BAD_REQUEST);
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
            details.add(error.getField() + ": " + error.getDefaultMessage());
        }
        
        ErrorResponse errorResponse = new ErrorResponse(
                "VALIDATION_ERROR",
                "Validation failed",
                details
        );
        
        logger.error("Validation error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.BAD_REQUEST);
    }
    
    /**
     * Handles authentication exceptions.
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAuthenticationExceptions(
            AuthenticationException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "AUTHENTICATION_ERROR",
                "Authentication failed",
                List.of(ex.getMessage())
        );
        
        logger.error("Authentication error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.UNAUTHORIZED);
    }
    
    /**
     * Handles authorization exceptions.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAuthorizationExceptions(
            AccessDeniedException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "AUTHORIZATION_ERROR",
                "Access denied",
                List.of(ex.getMessage())
        );
        
        logger.error("Authorization error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.FORBIDDEN);
    }
    
    /**
     * Handles BadCredentialsException.
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleBadCredentialsException(
            BadCredentialsException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "BAD_CREDENTIALS_ERROR",
                "Invalid credentials",
                List.of("Invalid username or password")
        );
        
        logger.error("Bad credentials error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.UNAUTHORIZED);
    }
    
    /**
     * Handles general exceptions.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleGlobalExceptions(
            Exception ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "INTERNAL_SERVER_ERROR",
                "An unexpected error occurred",
                List.of(ex.getMessage())
        );
        
        logger.error("Global error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
    }
    
    /**
     * Handles specific business exceptions.
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleBusinessExceptions(
            RuntimeException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "BUSINESS_ERROR",
                "A business error occurred",
                List.of(ex.getMessage())
        );
        
        logger.error("Business error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.BAD_REQUEST);
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
            details.add(error.getField() + ": " + error.getDefaultMessage());
        }
        
        ErrorResponse errorResponse = new ErrorResponse(
                "VALIDATION_ERROR",
                "Validation failed",
                details
        );
        
        logger.error("Validation error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.BAD_REQUEST);
    }
    
    /**
     * Handles authentication exceptions.
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAuthenticationExceptions(
            AuthenticationException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "AUTHENTICATION_ERROR",
                "Authentication failed",
                List.of(ex.getMessage())
        );
        
        logger.error("Authentication error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.UNAUTHORIZED);
    }
    
    /**
     * Handles authorization exceptions.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAuthorizationExceptions(
            AccessDeniedException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "AUTHORIZATION_ERROR",
                "Access denied",
                List.of(ex.getMessage())
        );
        
        logger.error("Authorization error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.FORBIDDEN);
    }
    
    /**
     * Handles BadCredentialsException.
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleBadCredentialsException(
            BadCredentialsException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "BAD_CREDENTIALS_ERROR",
                "Invalid credentials",
                List.of("Invalid username or password")
        );
        
        logger.error("Bad credentials error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.UNAUTHORIZED);
    }
    
    /**
     * Handles general exceptions.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleGlobalExceptions(
            Exception ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "INTERNAL_SERVER_ERROR",
                "An unexpected error occurred",
                List.of(ex.getMessage())
        );
        
        logger.error("Global error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
    }
    
    /**
     * Handles specific business exceptions.
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleBusinessExceptions(
            RuntimeException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "BUSINESS_ERROR",
                "A business error occurred",
                List.of(ex.getMessage())
        );
        
        logger.error("Business error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.BAD_REQUEST);
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
            details.add(error.getField() + ": " + error.getDefaultMessage());
        }
        
        ErrorResponse errorResponse = new ErrorResponse(
                "VALIDATION_ERROR",
                "Validation failed",
                details
        );
        
        logger.error("Validation error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.BAD_REQUEST);
    }
    
    /**
     * Handles authentication exceptions.
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAuthenticationExceptions(
            AuthenticationException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "AUTHENTICATION_ERROR",
                "Authentication failed",
                List.of(ex.getMessage())
        );
        
        logger.error("Authentication error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.UNAUTHORIZED);
    }
    
    /**
     * Handles authorization exceptions.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAuthorizationExceptions(
            AccessDeniedException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "AUTHORIZATION_ERROR",
                "Access denied",
                List.of(ex.getMessage())
        );
        
        logger.error("Authorization error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.FORBIDDEN);
    }
    
    /**
     * Handles BadCredentialsException.
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleBadCredentialsException(
            BadCredentialsException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "BAD_CREDENTIALS_ERROR",
                "Invalid credentials",
                List.of("Invalid username or password")
        );
        
        logger.error("Bad credentials error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.UNAUTHORIZED);
    }
    
    /**
     * Handles general exceptions.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleGlobalExceptions(
            Exception ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "INTERNAL_SERVER_ERROR",
                "An unexpected error occurred",
                List.of(ex.getMessage())
        );
        
        logger.error("Global error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
    }
    
    /**
     * Handles specific business exceptions.
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleBusinessExceptions(
            RuntimeException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "BUSINESS_ERROR",
                "A business error occurred",
                List.of(ex.getMessage())
        );
        
        logger.error("Business error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.BAD_REQUEST);
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
            details.add(error.getField() + ": " + error.getDefaultMessage());
        }
        
        ErrorResponse errorResponse = new ErrorResponse(
                "VALIDATION_ERROR",
                "Validation failed",
                details
        );
        
        logger.error("Validation error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.BAD_REQUEST);
    }
    
    /**
     * Handles authentication exceptions.
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAuthenticationExceptions(
            AuthenticationException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "AUTHENTICATION_ERROR",
                "Authentication failed",
                List.of(ex.getMessage())
        );
        
        logger.error("Authentication error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.UNAUTHORIZED);
    }
    
    /**
     * Handles authorization exceptions.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAuthorizationExceptions(
            AccessDeniedException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "AUTHORIZATION_ERROR",
                "Access denied",
                List.of(ex.getMessage())
        );
        
        logger.error("Authorization error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.FORBIDDEN);
    }
    
    /**
     * Handles BadCredentialsException.
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleBadCredentialsException(
            BadCredentialsException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "BAD_CREDENTIALS_ERROR",
                "Invalid credentials",
                List.of("Invalid username or password")
        );
        
        logger.error("Bad credentials error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.UNAUTHORIZED);
    }
    
    /**
     * Handles general exceptions.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleGlobalExceptions(
            Exception ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "INTERNAL_SERVER_ERROR",
                "An unexpected error occurred",
                List.of(ex.getMessage())
        );
        
        logger.error("Global error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
    }
    
    /**
     * Handles specific business exceptions.
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleBusinessExceptions(
            RuntimeException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "BUSINESS_ERROR",
                "A business error occurred",
                List.of(ex.getMessage())
        );
        
        logger.error("Business error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.BAD_REQUEST);
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
            details.add(error.getField() + ": " + error.getDefaultMessage());
        }
        
        ErrorResponse errorResponse = new ErrorResponse(
                "VALIDATION_ERROR",
                "Validation failed",
                details
        );
        
        logger.error("Validation error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.BAD_REQUEST);
    }
    
    /**
     * Handles authentication exceptions.
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAuthenticationExceptions(
            AuthenticationException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "AUTHENTICATION_ERROR",
                "Authentication failed",
                List.of(ex.getMessage())
        );
        
        logger.error("Authentication error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.UNAUTHORIZED);
    }
    
    /**
     * Handles authorization exceptions.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAuthorizationExceptions(
            AccessDeniedException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "AUTHORIZATION_ERROR",
                "Access denied",
                List.of(ex.getMessage())
        );
        
        logger.error("Authorization error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.FORBIDDEN);
    }
    
    /**
     * Handles BadCredentialsException.
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleBadCredentialsException(
            BadCredentialsException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "BAD_CREDENTIALS_ERROR",
                "Invalid credentials",
                List.of("Invalid username or password")
        );
        
        logger.error("Bad credentials error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.UNAUTHORIZED);
    }
    
    /**
     * Handles general exceptions.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleGlobalExceptions(
            Exception ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "INTERNAL_SERVER_ERROR",
                "An unexpected error occurred",
                List.of(ex.getMessage())
        );
        
        logger.error("Global error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
    }
    
    /**
     * Handles specific business exceptions.
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleBusinessExceptions(
            RuntimeException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "BUSINESS_ERROR",
                "A business error occurred",
                List.of(ex.getMessage())
        );
        
        logger.error("Business error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.BAD_REQUEST);
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
            details.add(error.getField() + ": " + error.getDefaultMessage());
        }
        
        ErrorResponse errorResponse = new ErrorResponse(
                "VALIDATION_ERROR",
                "Validation failed",
                details
        );
        
        logger.error("Validation error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.BAD_REQUEST);
    }
    
    /**
     * Handles authentication exceptions.
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAuthenticationExceptions(
            AuthenticationException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "AUTHENTICATION_ERROR",
                "Authentication failed",
                List.of(ex.getMessage())
        );
        
        logger.error("Authentication error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.UNAUTHORIZED);
    }
    
    /**
     * Handles authorization exceptions.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAuthorizationExceptions(
            AccessDeniedException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "AUTHORIZATION_ERROR",
                "Access denied",
                List.of(ex.getMessage())
        );
        
        logger.error("Authorization error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.FORBIDDEN);
    }
    
    /**
     * Handles BadCredentialsException.
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleBadCredentialsException(
            BadCredentialsException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "BAD_CREDENTIALS_ERROR",
                "Invalid credentials",
                List.of("Invalid username or password")
        );
        
        logger.error("Bad credentials error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.UNAUTHORIZED);
    }
    
    /**
     * Handles general exceptions.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleGlobalExceptions(
            Exception ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "INTERNAL_SERVER_ERROR",
                "An unexpected error occurred",
                List.of(ex.getMessage())
        );
        
        logger.error("Global error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
    }
    
    /**
     * Handles specific business exceptions.
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleBusinessExceptions(
            RuntimeException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "BUSINESS_ERROR",
                "A business error occurred",
                List.of(ex.getMessage())
        );
        
        logger.error("Business error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.BAD_REQUEST);
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
            details.add(error.getField() + ": " + error.getDefaultMessage());
        }
        
        ErrorResponse errorResponse = new ErrorResponse(
                "VALIDATION_ERROR",
                "Validation failed",
                details
        );
        
        logger.error("Validation error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.BAD_REQUEST);
    }
    
    /**
     * Handles authentication exceptions.
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAuthenticationExceptions(
            AuthenticationException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "AUTHENTICATION_ERROR",
                "Authentication failed",
                List.of(ex.getMessage())
        );
        
        logger.error("Authentication error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.UNAUTHORIZED);
    }
    
    /**
     * Handles authorization exceptions.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAuthorizationExceptions(
            AccessDeniedException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "AUTHORIZATION_ERROR",
                "Access denied",
                List.of(ex.getMessage())
        );
        
        logger.error("Authorization error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.FORBIDDEN);
    }
    
    /**
     * Handles BadCredentialsException.
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleBadCredentialsException(
            BadCredentialsException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "BAD_CREDENTIALS_ERROR",
                "Invalid credentials",
                List.of("Invalid username or password")
        );
        
        logger.error("Bad credentials error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.UNAUTHORIZED);
    }
    
    /**
     * Handles general exceptions.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleGlobalExceptions(
            Exception ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "INTERNAL_SERVER_ERROR",
                "An unexpected error occurred",
                List.of(ex.getMessage())
        );
        
        logger.error("Global error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
    }
    
    /**
     * Handles specific business exceptions.
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleBusinessExceptions(
            RuntimeException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "BUSINESS_ERROR",
                "A business error occurred",
                List.of(ex.getMessage())
        );
        
        logger.error("Business error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.BAD_REQUEST);
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
            details.add(error.getField() + ": " + error.getDefaultMessage());
        }
        
        ErrorResponse errorResponse = new ErrorResponse(
                "VALIDATION_ERROR",
                "Validation failed",
                details
        );
        
        logger.error("Validation error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.BAD_REQUEST);
    }
    
    /**
     * Handles authentication exceptions.
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAuthenticationExceptions(
            AuthenticationException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "AUTHENTICATION_ERROR",
                "Authentication failed",
                List.of(ex.getMessage())
        );
        
        logger.error("Authentication error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.UNAUTHORIZED);
    }
    
    /**
     * Handles authorization exceptions.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAuthorizationExceptions(
            AccessDeniedException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "AUTHORIZATION_ERROR",
                "Access denied",
                List.of(ex.getMessage())
        );
        
        logger.error("Authorization error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.FORBIDDEN);
    }
    
    /**
     * Handles BadCredentialsException.
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleBadCredentialsException(
            BadCredentialsException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "BAD_CREDENTIALS_ERROR",
                "Invalid credentials",
                List.of("Invalid username or password")
        );
        
        logger.error("Bad credentials error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.UNAUTHORIZED);
    }
    
    /**
     * Handles general exceptions.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleGlobalExceptions(
            Exception ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "INTERNAL_SERVER_ERROR",
                "An unexpected error occurred",
                List.of(ex.getMessage())
        );
        
        logger.error("Global error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
    }
    
    /**
     * Handles specific business exceptions.
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleBusinessExceptions(
            RuntimeException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "BUSINESS_ERROR",
                "A business error occurred",
                List.of(ex.getMessage())
        );
        
        logger.error("Business error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.BAD_REQUEST);
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
            details.add(error.getField() + ": " + error.getDefaultMessage());
        }
        
        ErrorResponse errorResponse = new ErrorResponse(
                "VALIDATION_ERROR",
                "Validation failed",
                details
        );
        
        logger.error("Validation error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.BAD_REQUEST);
    }
    
    /**
     * Handles authentication exceptions.
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAuthenticationExceptions(
            AuthenticationException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "AUTHENTICATION_ERROR",
                "Authentication failed",
                List.of(ex.getMessage())
        );
        
        logger.error("Authentication error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.UNAUTHORIZED);
    }
    
    /**
     * Handles authorization exceptions.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAuthorizationExceptions(
            AccessDeniedException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "AUTHORIZATION_ERROR",
                "Access denied",
                List.of(ex.getMessage())
        );
        
        logger.error("Authorization error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.FORBIDDEN);
    }
    
    /**
     * Handles BadCredentialsException.
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleBadCredentialsException(
            BadCredentialsException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "BAD_CREDENTIALS_ERROR",
                "Invalid credentials",
                List.of("Invalid username or password")
        );
        
        logger.error("Bad credentials error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.UNAUTHORIZED);
    }
    
    /**
     * Handles general exceptions.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleGlobalExceptions(
            Exception ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "INTERNAL_SERVER_ERROR",
                "An unexpected error occurred",
                List.of(ex.getMessage())
        );
        
        logger.error("Global error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
    }
    
    /**
     * Handles specific business exceptions.
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleBusinessExceptions(
            RuntimeException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "BUSINESS_ERROR",
                "A business error occurred",
                List.of(ex.getMessage())
        );
        
        logger.error("Business error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.BAD_REQUEST);
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
            details.add(error.getField() + ": " + error.getDefaultMessage());
        }
        
        ErrorResponse errorResponse = new ErrorResponse(
                "VALIDATION_ERROR",
                "Validation failed",
                details
        );
        
        logger.error("Validation error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.BAD_REQUEST);
    }
    
    /**
     * Handles authentication exceptions.
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAuthenticationExceptions(
            AuthenticationException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "AUTHENTICATION_ERROR",
                "Authentication failed",
                List.of(ex.getMessage())
        );
        
        logger.error("Authentication error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.UNAUTHORIZED);
    }
    
    /**
     * Handles authorization exceptions.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAuthorizationExceptions(
            AccessDeniedException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "AUTHORIZATION_ERROR",
                "Access denied",
                List.of(ex.getMessage())
        );
        
        logger.error("Authorization error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.FORBIDDEN);
    }
    
    /**
     * Handles BadCredentialsException.
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleBadCredentialsException(
            BadCredentialsException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "BAD_CREDENTIALS_ERROR",
                "Invalid credentials",
                List.of("Invalid username or password")
        );
        
        logger.error("Bad credentials error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.UNAUTHORIZED);
    }
    
    /**
     * Handles general exceptions.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleGlobalExceptions(
            Exception ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "INTERNAL_SERVER_ERROR",
                "An unexpected error occurred",
                List.of(ex.getMessage())
        );
        
        logger.error("Global error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
    }
    
    /**
     * Handles specific business exceptions.
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleBusinessExceptions(
            RuntimeException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "BUSINESS_ERROR",
                "A business error occurred",
                List.of(ex.getMessage())
        );
        
        logger.error("Business error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.BAD_REQUEST);
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
            details.add(error.getField() + ": " + error.getDefaultMessage());
        }
        
        ErrorResponse errorResponse = new ErrorResponse(
                "VALIDATION_ERROR",
                "Validation failed",
                details
        );
        
        logger.error("Validation error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.BAD_REQUEST);
    }
    
    /**
     * Handles authentication exceptions.
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAuthenticationExceptions(
            AuthenticationException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "AUTHENTICATION_ERROR",
                "Authentication failed",
                List.of(ex.getMessage())
        );
        
        logger.error("Authentication error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.UNAUTHORIZED);
    }
    
    /**
     * Handles authorization exceptions.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAuthorizationExceptions(
            AccessDeniedException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "AUTHORIZATION_ERROR",
                "Access denied",
                List.of(ex.getMessage())
        );
        
        logger.error("Authorization error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.FORBIDDEN);
    }
    
    /**
     * Handles BadCredentialsException.
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleBadCredentialsException(
            BadCredentialsException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "BAD_CREDENTIALS_ERROR",
                "Invalid credentials",
                List.of("Invalid username or password")
        );
        
        logger.error("Bad credentials error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.UNAUTHORIZED);
    }
    
    /**
     * Handles general exceptions.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleGlobalExceptions(
            Exception ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "INTERNAL_SERVER_ERROR",
                "An unexpected error occurred",
                List.of(ex.getMessage())
        );
        
        logger.error("Global error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
    }
    
    /**
     * Handles specific business exceptions.
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleBusinessExceptions(
            RuntimeException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse(
                "BUSINESS_ERROR",
                "A business error occurred",
                List.of(ex.getMessage())
        );
        
        logger.error("Business error: {}", errorResponse.getMessage(), ex);
        return new ResponseEntity<>(ApiResponse.error(errorResponse.getMessage()), HttpStatus.BAD_REQUEST);
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
