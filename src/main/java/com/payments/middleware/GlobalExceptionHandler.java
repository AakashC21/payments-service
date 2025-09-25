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
        
        ErrorResponse errorResponse = new ErrorResponse("VALIDATION_ERROR", "Validation failed", details);
        errorResponse.setCorrelationId(CorrelationIdUtil.getCorrelationId());
        
        return new ResponseEntity<>(new ApiResponse<>(false, "Validation failed", errorResponse), HttpStatus.BAD_REQUEST);
    }
    
    /**
     * Handles AuthenticationExceptions (e.g., BadCredentialsException, AuthenticationException).
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAuthenticationExceptions(
            AuthenticationException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse("AUTHENTICATION_ERROR", ex.getMessage());
        errorResponse.setCorrelationId(CorrelationIdUtil.getCorrelationId());
        
        return new ResponseEntity<>(new ApiResponse<>(false, "Authentication failed", errorResponse), HttpStatus.UNAUTHORIZED);
    }
    
    /**
     * Handles AccessDeniedExceptions (e.g., AccessDeniedException).
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleAccessDeniedExceptions(
            AccessDeniedException ex, WebRequest request) {
        
        ErrorResponse errorResponse = new ErrorResponse("ACCESS_DENIED", ex.getMessage());
        errorResponse.setCorrelationId(CorrelationIdUtil.getCorrelationId());
        
        return new ResponseEntity<>(new ApiResponse<>(false, "Access denied", errorResponse), HttpStatus.FORBIDDEN);
    }
    
    /**
     * Handles general exceptions.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<ErrorResponse>> handleGlobalExceptions(
            Exception ex, WebRequest request) {
        
        logger.error("Unhandled exception: {}", ex.getMessage(), ex);
        
        ErrorResponse errorResponse = new ErrorResponse("INTERNAL_SERVER_ERROR", "An unexpected error occurred");
        errorResponse.setCorrelationId(CorrelationIdUtil.getCorrelationId());
        
        return new ResponseEntity<>(new ApiResponse<>(false, "Internal server error", errorResponse), HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
```

