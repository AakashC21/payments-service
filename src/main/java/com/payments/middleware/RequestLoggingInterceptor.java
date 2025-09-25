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
