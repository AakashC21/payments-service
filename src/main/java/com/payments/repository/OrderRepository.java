package com.payments.repository;

import com.payments.model.entity.Order;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Repository interface for Order entity operations.
 */
@Repository
public interface OrderRepository extends JpaRepository<Order, Long> {
    
    Optional<Order> findByOrderNumber(String orderNumber);
    
    List<Order> findByUserId(Long userId);
    
    List<Order> findByUserIdAndStatus(Long userId, Order.OrderStatus status);
    
    @Query("SELECT o FROM Order o WHERE o.status = :status")
    List<Order> findByStatus(@Param("status") Order.OrderStatus status);
}

```

```java:src/main/java/com/payments/repository/PaymentRepository.java
package com.payments.repository;

import com.payments.model.entity.Payment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Repository interface for Payment entity operations.
 */
@Repository
public interface PaymentRepository extends JpaRepository<Payment, Long> {
    
    Optional<Payment> findByAuthorizeNetTransactionId(String authorizeNetTransactionId);
    
    List<Payment> findByOrderId(Long orderId);
    
    List<Payment> findByUserId(Long userId);
    
    List<Payment> findByStatus(Payment.PaymentStatus status);
    
    @Query("SELECT p FROM Payment p WHERE p.orderId = :orderId AND p.status = :status")
    List<Payment> findByOrderIdAndStatus(@Param("orderId") Long orderId, @Param("status") Payment.PaymentStatus status);
}

```

```java:src/main/java/com/payments/repository/SubscriptionRepository.java
package com.payments.repository;

import com.payments.model.entity.Subscription;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Repository interface for Subscription entity operations.
 */
@Repository
public interface SubscriptionRepository extends JpaRepository<Subscription, Long> {
    
    Optional<Subscription> findByAuthorizeNetSubscriptionId(String authorizeNetSubscriptionId);
    
    List<Subscription> findByUserId(Long userId);
    
    List<Subscription> findByStatus(Subscription.SubscriptionStatus status);
    
    List<Subscription> findByUserIdAndStatus(Long userId, Subscription.SubscriptionStatus status);
    
    @Query("SELECT s FROM Subscription s WHERE s.nextBillingDate <= :date AND s.status = 'ACTIVE'")
    List<Subscription> findSubscriptionsDueForBilling(@Param("date") LocalDateTime date);
    
    @Query("SELECT s FROM Subscription s WHERE s.userId = :userId AND s.status = 'ACTIVE'")
    List<Subscription> findActiveSubscriptionsByUserId(@Param("userId") Long userId);
}

```

```java:src/main/java/com/payments/repository/IdempotencyKeyRepository.java
package com.payments.repository;

import com.payments.model.entity.IdempotencyKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Repository interface for IdempotencyKey entity operations.
 */
@Repository
public interface IdempotencyKeyRepository extends JpaRepository<IdempotencyKey, Long> {
    
    Optional<IdempotencyKey> findByKeyValue(String keyValue);
    
    @Query("SELECT ik FROM IdempotencyKey ik WHERE ik.keyValue = :keyValue AND ik.endpoint = :endpoint")
    Optional<IdempotencyKey> findByKeyValueAndEndpoint(@Param("keyValue") String keyValue, @Param("endpoint") String endpoint);
    
    @Modifying
    @Query("DELETE FROM IdempotencyKey ik WHERE ik.createdAt < :expiryDate")
    int deleteExpiredKeys(@Param("expiryDate") LocalDateTime expiryDate);
}

```

```java:src/main/java/com/payments/repository/WebhookEventRepository.java
package com.payments.repository;

import com.payments.model.entity.WebhookEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Repository interface for WebhookEvent entity operations.
 */
@Repository
public interface WebhookEventRepository extends JpaRepository<WebhookEvent, Long> {
    
    List<WebhookEvent> findByStatus(WebhookEvent.ProcessingStatus status);
    
    List<WebhookEvent> findByEventType(String eventType);
    
    @Query("SELECT we FROM WebhookEvent we WHERE we.createdAt >= :fromDate AND we.createdAt <= :toDate")
    List<WebhookEvent> findByDateRange(@Param("fromDate") LocalDateTime fromDate, @Param("toDate") LocalDateTime toDate);
    
    @Query("SELECT we FROM WebhookEvent we WHERE we.status = 'RETRYING' AND we.retryCount < 3")
    List<WebhookEvent> findRetryableEvents();
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
import org.springframework.beans.factory.annotation.Value;
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
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    
    @Value("${app.security.jwt.secret}")
    private String jwtSecret;
    
    public JwtAuthenticationFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
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

```java:src/main/java/com/payments/metrics/PaymentMetrics.java
package com.payments.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Component;

/**
 * Metrics collection for payment operations.
 * 
 * Key features:
 * - Payment success/failure counters
 * - Webhook processing metrics
 * - Idempotency conflict tracking
 * - Performance timing metrics
 */
@Component
public class PaymentMetrics {
    
    private final Counter paymentsTotal;
    private final Counter paymentsSuccessful;
    private final Counter paymentsFailed;
    private final Counter webhooksProcessedTotal;
    private final Counter webhooksProcessedSuccessful;
    private final Counter webhooksProcessedFailed;
    private final Counter idempotencyConflicts;
    private final Timer paymentProcessingTime;
    private final Timer webhookProcessingTime;
    
    public PaymentMetrics(MeterRegistry meterRegistry) {
        this.paymentsTotal = Counter.builder("payments_total")
                .description("Total number of payment attempts")
                .register(meterRegistry);
        
        this.paymentsSuccessful = Counter.builder("payments_successful_total")
                .description("Total number of successful payments")
                .register(meterRegistry);
        
        this.paymentsFailed = Counter.builder("payments_failed_total")
                .description("Total number of failed payments")
                .register(meterRegistry);
        
        this.webhooksProcessedTotal = Counter.builder("webhooks_processed_total")
                .description("Total number of webhook events processed")
                .register(meterRegistry);
        
        this.webhooksProcessedSuccessful = Counter.builder("webhooks_processed_successful_total")
                .description("Total number of successfully processed webhooks")
                .register(meterRegistry);
        
        this.webhooksProcessedFailed = Counter.builder("webhooks_processed_failed_total")
                .description("Total number of failed webhook processing attempts")
                .register(meterRegistry);
        
        this.idempotencyConflicts = Counter.builder("idempotency_conflicts_total")
                .description("Total number of idempotency key conflicts")
                .register(meterRegistry);
        
        this.paymentProcessingTime = Timer.builder("payment_processing_time")
                .description("Time taken to process payments")
                .register(meterRegistry);
        
        this.webhookProcessingTime = Timer.builder("webhook_processing_time")
                .description("Time taken to process webhook events")
                .register(meterRegistry);
    }
    
    /**
     * Increments the total payments counter.
     */
    public void incrementPaymentsTotal() {
        paymentsTotal.increment();
    }
    
    /**
     * Increments the successful payments counter.
     */
    public void incrementPaymentsSuccessful() {
        paymentsSuccessful.increment();
    }
    
    /**
     * Increments the failed payments counter.
     */
    public void incrementPaymentsFailed() {
        paymentsFailed.increment();
    }
    
    /**
     * Increments the total webhooks processed counter.
     */
    public void incrementWebhooksProcessedTotal() {
        webhooksProcessedTotal.increment();
    }
    
    /**
     * Increments the successful webhooks processed counter.
     */
    public void incrementWebhooksProcessedSuccessful() {
        webhooksProcessedSuccessful.increment();
    }
    
    /**
     * Increments the failed webhooks processed counter.
     */
    public void incrementWebhooksProcessedFailed() {
        webhooksProcessedFailed.increment();
    }
    
    /**
     * Increments the idempotency conflicts counter.
     */
    public void incrementIdempotencyConflicts() {
        idempotencyConflicts.increment();
    }
    
    /**
     * Gets the payment processing timer.
     * 
     * @return Timer for payment processing time
     */
    public Timer getPaymentProcessingTime() {
        return paymentProcessingTime;
    }
    
    /**
     * Gets the webhook processing timer.
     * 
     * @return Timer for webhook processing time
     */
    public Timer getWebhookProcessingTime() {
        return webhookProcessingTime;
    }
}

```

```java:src/main/java/com/payments/gateway/AuthorizeNetGateway.java
package com.payments.gateway;

import com.payments.model.dto.PaymentRequest;

/**
 * Interface for Authorize.Net payment gateway operations.
 */
public interface AuthorizeNetGateway {
    
    String processPurchase(PaymentRequest request);
    
    String authorizePayment(PaymentRequest request);
    
    String capturePayment(String authorizationTransactionId, String amount);
    
    String refundPayment(String originalTransactionId, String amount);
    
    String voidPayment(String transactionId);
    
    String createSubscription(com.payments.model.entity.Subscription subscription);
    
    String updateSubscription(String subscriptionId, com.payments.model.entity.Subscription subscription);
    
    String cancelSubscription(String subscriptionId);
    
    boolean verifyWebhookSignature(String payload, String signature);
}

```

```java:src/main/java/com/payments/gateway/AuthorizeNetGatewayImpl.java
package com.payments.gateway;

import com.payments.model.dto.PaymentRequest;
import com.payments.model.entity.Subscription;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * Implementation of Authorize.Net payment gateway operations.
 * This is a mock implementation for development/testing purposes.
 */
@Component
public class AuthorizeNetGatewayImpl implements AuthorizeNetGateway {
    
    private static final Logger logger = LoggerFactory.getLogger(AuthorizeNetGatewayImpl.class);
    
    @Value("${app.authorize-net.login-id}")
    private String loginId;
    
    @Value("${app.authorize-net.transaction-key}")
    private String transactionKey;
    
    @Value("${app.authorize-net.sandbox:true}")
    private boolean sandbox;
    
    @Override
    public String processPurchase(PaymentRequest request) {
        logger.info("Processing purchase for order: {} with amount: {}", request.getOrderNumber(), request.getAmount());
        
        // Mock implementation - generate a fake transaction ID
        String transactionId = "TXN_" + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
        logger.info("Purchase processed successfully with transaction ID: {}", transactionId);
        
        return transactionId;
    }
    
    @Override
    public String authorizePayment(PaymentRequest request) {
        logger.info("Authorizing payment for order: {} with amount: {}", request.getOrderNumber(), request.getAmount());
        
        String transactionId = "AUTH_" + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
        logger.info("Payment authorized successfully with transaction ID: {}", transactionId);
        
        return transactionId;
    }
    
    @Override
    public String capturePayment(String authorizationTransactionId, String amount) {
        logger.info("Capturing payment for authorization: {} with amount: {}", authorizationTransactionId, amount);
        
        String transactionId = "CAPT_" + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
        logger.info("Payment captured successfully with transaction ID: {}", transactionId);
        
        return transactionId;
    }
    
    @Override
    public String refundPayment(String originalTransactionId, String amount) {
        logger.info("Processing refund for transaction: {} with amount: {}", originalTransactionId, amount);
        
        String transactionId = "REF_" + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
        logger.info("Refund processed successfully with transaction ID: {}", transactionId);
        
        return transactionId;
    }
    
    @Override
    public String voidPayment(String transactionId) {
        logger.info("Voiding payment for transaction: {}", transactionId);
        
        String voidTransactionId = "VOID_" + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
        logger.info("Payment voided successfully with transaction ID: {}", voidTransactionId);
        
        return voidTransactionId;
    }
    
    @Override
    public String createSubscription(Subscription subscription) {
        logger.info("Creating subscription for user: {} with plan: {}", subscription.getUserId(), subscription.getPlanName());
        
        String subscriptionId = "SUB_" + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
        logger.info("Subscription created successfully with ID: {}", subscriptionId);
        
        return subscriptionId;
    }
    
    @Override
    public String updateSubscription(String subscriptionId, Subscription subscription) {
        logger.info("Updating subscription: {}", subscriptionId);
        
        String updatedSubscriptionId = "SUB_UPDATED_" + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
        logger.info("Subscription updated successfully with ID: {}", updatedSubscriptionId);
        
        return updatedSubscriptionId;
    }
    
    @Override
    public String cancelSubscription(String subscriptionId) {
        logger.info("Cancelling subscription: {}", subscriptionId);
        
        String cancelledSubscriptionId = "SUB_CANCELLED_" + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
        logger.info("Subscription cancelled successfully with ID: {}", cancelledSubscriptionId);
        
        return cancelledSubscriptionId;
    }
    
    @Override
    public boolean verifyWebhookSignature(String payload, String signature) {
        logger.info("Verifying webhook signature");
        
        // Mock implementation - always return true for development
        // In production, implement proper HMAC verification
        return true;
    }
}

```

```java:src/main/java/com/payments/service/IdempotencyService.java
package com.payments.service;

import com.payments.model.entity.IdempotencyKey;
import com.payments.repository.IdempotencyKeyRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.concurrent.TimeUnit;

/**
 * Service for idempotency key management.
 */
@Service
@Transactional
public class IdempotencyService {
    
    private static final Logger logger = LoggerFactory.getLogger(IdempotencyService.class);
    
    private final IdempotencyKeyRepository idempotencyKeyRepository;
    private final RedisTemplate<String, Object> redisTemplate;
    
    public IdempotencyService(IdempotencyKeyRepository idempotencyKeyRepository, RedisTemplate<String, Object> redisTemplate) {
        this.idempotencyKeyRepository = idempotencyKeyRepository;
        this.redisTemplate = redisTemplate;
    }
    
    public String checkIdempotency(String keyValue, String endpoint, String correlationId) {
        logger.debug("Checking idempotency for key: {} and endpoint: {}", keyValue, endpoint);
        
        // Check Redis cache first
        String cacheKey = "idempotency:" + keyValue + ":" + endpoint;
        String cachedResponse = (String) redisTemplate.opsForValue().get(cacheKey);
        
        if (cachedResponse != null) {
            logger.debug("Found cached response for idempotency key: {}", keyValue);
            return cachedResponse;
        }
        
        // Check database
        IdempotencyKey idempotencyKey = idempotencyKeyRepository.findByKeyValueAndEndpoint(keyValue, endpoint).orElse(null);
        
        if (idempotencyKey != null && !isExpired(idempotencyKey)) {
            // Cache the response in Redis
            redisTemplate.opsForValue().set(cacheKey, idempotencyKey.getResponseBody(), 24, TimeUnit.HOURS);
            
            logger.debug("Found database response for idempotency key: {}", keyValue);
            return idempotencyKey.getResponseBody();
        }
        
        return null;
    }
    
    public void storeIdempotencyKey(String keyValue, String endpoint, String requestBody, String responseBody, String correlationId) {
        logger.debug("Storing idempotency key: {} for endpoint: {}", keyValue, endpoint);
        
        // Store in database
        IdempotencyKey idempotencyKey = new IdempotencyKey();
        idempotencyKey.setKeyValue(keyValue);
        idempotencyKey.setEndpoint(endpoint);
        idempotencyKey.setRequestBody(requestBody);
        idempotencyKey.setResponseBody(responseBody);
        idempotencyKey.setCorrelationId(correlationId);
        idempotencyKey.setCreatedAt(LocalDateTime.now());
        
        idempotencyKeyRepository.save(idempotencyKey);
        
        // Cache in Redis
        String cacheKey = "idempotency:" + keyValue + ":" + endpoint;
        redisTemplate.opsForValue().set(cacheKey, responseBody, 24, TimeUnit.HOURS);
        
        logger.debug("Idempotency key stored successfully: {}", keyValue);
    }
    
    private boolean isExpired(IdempotencyKey idempotencyKey) {
        return idempotencyKey.getCreatedAt().isBefore(LocalDateTime.now().minusHours(24));
    }
}

```

```java:src/main/java/com/payments/service/AuthService.java
package com.payments.service;

import com.payments.model.dto.LoginRequest;
import com.payments.model.dto.LoginResponse;
import com.payments.model.entity.User;
import com.payments.repository.UserRepository;
import com.payments.util.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * Service for authentication operations.
 */
@Service
@Transactional
public class AuthService {
    
    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);
    
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    
    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }
    
    public LoginResponse authenticateUser(LoginRequest loginRequest) {
        logger.info("Authenticating user: {}", loginRequest.getEmail());
        
        User user = userRepository.findByEmail(loginRequest.getEmail())
            .orElseThrow(() -> new RuntimeException("Invalid credentials"));
        
        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid credentials");
        }
        
        String token = jwtUtil.generateToken(user.getEmail(), user.getId());
        
        return new LoginResponse(token, user.getId(), user.getEmail());
    }
    
    public User createUser(String email, String password, String firstName, String lastName) {
        logger.info("Creating user: {}", email);
        
        if (userRepository.existsByEmail(email)) {
            throw new RuntimeException("User already exists");
        }
        
        User user = new User();
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setActive(true);
        user.setCreatedAt(LocalDateTime.now());
        
        return userRepository.save(user);
    }
}

```

```yaml:src/main/resources/application.yml
server:
  port: 8080
  servlet:
    context-path: /

spring:
  application:
    name: payments-service
  
  profiles:
    active: dev
  
  datasource:
    url: jdbc:postgresql://localhost:5432/payments_db
    username: ${DB_USERNAME:payments_user}
    password: ${DB_PASSWORD:payments_pass}
    driver-class-name: org.postgresql.Driver
    
  jpa:
    hibernate:
      ddl-auto: validate
    show-sql: false
    properties:
      hibernate:
        dialect: org.hibernate.dialect.PostgreSQLDialect
        format_sql: true
        jdbc:
          batch_size: 25
          batch_versioned_data: true
        order_inserts: true
        order_updates: true
        connection:
          provider_disables_autocommit: true
  
  data:
    redis:
      host: ${REDIS_HOST:localhost}
      port: ${REDIS_PORT:6379}
      password: ${REDIS_PASSWORD:}
      database: ${REDIS_DATABASE:0}
      timeout: 2000ms
      lettuce:
        pool:
          max-active: 8
          max-idle: 8
          min-idle: 0
          max-wait: -1ms
  
  liquibase:
    change-log: classpath:db/migration/changelog.xml
    enabled: true

# Application specific configuration
app:
  security:
    jwt:
      secret: ${JWT_SECRET:mySecretKey}
      expiration: 86400 # 24 hours in seconds
  
  idempotency:
    ttl-hours: 24
    redis-ttl-minutes: 60
  
  authorize-net:
    login-id: ${AUTHORIZE_NET_LOGIN_ID:your_login_id}
    transaction-key: ${AUTHORIZE_NET_TRANSACTION_KEY:your_transaction_key}
    sandbox: ${AUTHORIZE_NET_SANDBOX:true}
    webhook-signature-key: ${AUTHORIZE_NET_WEBHOOK_SIGNATURE_KEY:your_webhook_key}

# Management endpoints
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus
  endpoint:
    health:
      show-details: when-authorized
    metrics:
      enabled: true
  metrics:
    export:
      prometheus:
        enabled: true

# Logging configuration
logging:
  level:
    com.payments: INFO
    org.springframework.security: DEBUG
    org.hibernate.SQL: DEBUG
    org.hibernate.type.descriptor.sql.BasicBinder: TRACE
  pattern:
    console: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level [%X{correlationId}] %logger{36} - %msg%n"

# OpenAPI/Swagger configuration
springdoc:
  api-docs:
    path: /v3/api-docs
  swagger-ui:
    path: /swagger-ui.html
    operationsSorter: method
  show-actuator: true
```

```yaml:src/main/resources/application-dev.yml


```

```java:src/main/java/com/payments/model/entity/WebhookEvent.java
package com.payments.model.entity;

import jakarta.persistence.*;
import org.springframework.data.annotation.CreatedDate;

import java.time.LocalDateTime;

/**
 * Webhook event entity for storing incoming webhook events.
 */
@Entity
@Table(name = "webhook_events")
public class WebhookEvent {
    
    public enum ProcessingStatus {
        PENDING, PROCESSING, COMPLETED, FAILED, RETRYING
    }
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(name = "event_type", nullable = false)
    private String eventType;
    
    @Column(name = "payload", columnDefinition = "TEXT")
    private String payload;
    
    @Column(name = "signature")
    private String signature;
    
    @Column(name = "correlation_id")
    private String correlationId;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private ProcessingStatus status = ProcessingStatus.PENDING;
    
    @Column(name = "retry_count")
    private Integer retryCount = 0;
    
    @Column(name = "error_message", columnDefinition = "TEXT")
    private String errorMessage;
    
    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;
    
    @Column(name = "processed_at")
    private LocalDateTime processedAt;
    
    // Constructors
    public WebhookEvent() {}
    
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getEventType() { return eventType; }
    public void setEventType(String eventType) { this.eventType = eventType; }
    
    public String getPayload() { return payload; }
    public void setPayload(String payload) { this.payload = payload; }
    
    public String getSignature() { return signature; }
    public void setSignature(String signature) { this.signature = signature; }
    
    public String getCorrelationId() { return correlationId; }
    public void setCorrelationId(String correlationId) { this.correlationId = correlationId; }
    
    public ProcessingStatus getStatus() { return status; }
    public void setStatus(ProcessingStatus status) { this.status = status; }
    
    public Integer getRetryCount() { return retryCount; }
    public void setRetryCount(Integer retryCount) { this.retryCount = retryCount; }
    
    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
    
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    
    public LocalDateTime getProcessedAt() { return processedAt; }
    public void setProcessedAt(LocalDateTime processedAt) { this.processedAt = processedAt; }
}

```

```java:src/main/java/com/payments/model/dto/LoginRequest.java
package com.payments.model.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * Request DTO for user login.
 */
public class LoginRequest {
    
    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;
    
    @NotBlank(message = "Password is required")
    private String password;
    
    // Constructors
    public LoginRequest() {}
    
    public LoginRequest(String email, String password) {
        this.email = email;
        this.password = password;
    }
    
    // Getters and Setters
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
}

```

```java:src/main/java/com/payments/model/dto/LoginResponse.java
package com.payments.model.dto;

/**
 * Response DTO for user login.
 */
public class LoginResponse {
    
    private String token;
    private String tokenType = "Bearer";
    private Long expiresIn = 3600L;
    private Long userId;
    private String email;
    
    // Constructors
    public LoginResponse() {}
    
    public LoginResponse(String token, Long userId, String email) {
        this.token = token;
        this.userId = userId;
        this.email = email;
    }
    
    // Getters and Setters
    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }
    
    public String getTokenType() { return tokenType; }
    public void setTokenType(String tokenType) { this.tokenType = tokenType; }
    
    public Long getExpiresIn() { return expiresIn; }
    public void setExpiresIn(Long expiresIn) { this.expiresIn = expiresIn; }
    
    public Long getUserId() { return userId; }
    public void setUserId(Long userId) { this.userId = userId; }
    
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
}

```

```java:src/main/java/com/payments/model/dto/PaymentRequest.java
package com.payments.model.dto;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.math.BigDecimal;

/**
 * Request DTO for payment operations.
 */
public class PaymentRequest {
    
    @NotBlank(message = "Order number is required")
    private String orderNumber;
    
    @NotNull(message = "Amount is required")
    @DecimalMin(value = "0.01", message = "Amount must be greater than 0")
    private BigDecimal amount;
    
    @NotBlank(message = "Currency is required")
    private String currency = "USD";
    
    @NotBlank(message = "Payment method is required")
    private String paymentMethod;
    
    // Credit card details (for testing)
    private String cardNumber;
    private String expiryDate;
    private String cvv;
    
    // Constructors
    public PaymentRequest() {}
    
    // Getters and Setters
    public String getOrderNumber() { return orderNumber; }
    public void setOrderNumber(String orderNumber) { this.orderNumber = orderNumber; }
    
    public BigDecimal getAmount() { return amount; }
    public void setAmount(BigDecimal amount) { this.amount = amount; }
    
    public String getCurrency() { return currency; }
    public void setCurrency(String currency) { this.currency = currency; }
    
    public String getPaymentMethod() { return paymentMethod; }
    public void setPaymentMethod(String paymentMethod) { this.paymentMethod = paymentMethod; }
    
    public String getCardNumber() { return cardNumber; }
    public void setCardNumber(String cardNumber) { this.cardNumber = cardNumber; }
    
    public String getExpiryDate() { return expiryDate; }
    public void setExpiryDate(String expiryDate) { this.expiryDate = expiryDate; }
    
    public String getCvv() { return cvv; }
    public void setCvv(String cvv) { this.cvv = cvv; }
}

```

```java:src/main/java/com/payments/model/dto/PaymentResponse.java
package com.payments.model.dto;

import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * Response DTO for payment operations.
 */
public class PaymentResponse {
    
    private Long id;
    private String transactionId;
    private BigDecimal amount;
    private String currency;
    private String status;
    private String paymentMethod;
    private LocalDateTime createdAt;
    private LocalDateTime processedAt;
    
    // Constructors
    public PaymentResponse() {}
    
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getTransactionId() { return transactionId; }
    public void setTransactionId(String transactionId) { this.transactionId = transactionId; }
    
    public BigDecimal getAmount() { return amount; }
    public void setAmount(BigDecimal amount) { this.amount = amount; }
    
    public String getCurrency() { return currency; }
    public void setCurrency(String currency) { this.currency = currency; }
    
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    
    public String getPaymentMethod() { return paymentMethod; }
    public void setPaymentMethod(String paymentMethod) { this.paymentMethod = paymentMethod; }
    
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    
    public LocalDateTime getProcessedAt() { return processedAt; }
    public void setProcessedAt(LocalDateTime processedAt) { this.processedAt = processedAt; }
}

```

```java:src/main/java/com/payments/controller/AuthController.java
package com.payments.controller;

import com.payments.model.dto.ApiResponse;
import com.payments.model.dto.LoginRequest;
import com.payments.model.dto.LoginResponse;
import com.payments.service.AuthService;
import com.payments.util.CorrelationIdUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Controller for authentication operations.
 */
@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Authentication", description = "Authentication operations")
public class AuthController {
    
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    
    private final AuthService authService;
    
    public AuthController(AuthService authService) {
        this.authService = authService;
    }
    
    @PostMapping("/login")
    @Operation(summary = "User login", description = "Authenticates user and returns JWT token")
    public ResponseEntity<ApiResponse<LoginResponse>> login(@Valid @RequestBody LoginRequest loginRequest) {
        logger.info("Login attempt for user: {}", loginRequest.getEmail());
        
        try {
            LoginResponse response = authService.authenticateUser(loginRequest);
            ApiResponse<LoginResponse> apiResponse = ApiResponse.success("Login successful", response);
            apiResponse.setCorrelationId(CorrelationIdUtil.getCorrelationId());
            
            return ResponseEntity.ok(apiResponse);
            
        } catch (Exception e) {
            logger.error("Login failed for user: {}", loginRequest.getEmail(), e);
            throw e;
        }
    }
    
    @PostMapping("/register")
    @Operation(summary = "User registration", description = "Creates a new user account")
    public ResponseEntity<ApiResponse<String>> register(@Valid @RequestBody LoginRequest registerRequest) {
        logger.info("Registration attempt for user: {}", registerRequest.getEmail());
        
        try {
            authService.createUser(
                registerRequest.getEmail(),
                registerRequest.getPassword(),
                "Test",
                "User"
            );
            
            ApiResponse<String> apiResponse = ApiResponse.success("User created successfully", null);
            apiResponse.setCorrelationId(CorrelationIdUtil.getCorrelationId());
            
            return ResponseEntity.ok(apiResponse);
            
        } catch (Exception e) {
            logger.error("Registration failed for user: {}", registerRequest.getEmail(), e);
            throw e;
        }
    }
}

```

```java:src/main/java/com/payments/controller/PaymentController.java
package com.payments.controller;

import com.payments.model.dto.ApiResponse;
import com.payments.model.dto.PaymentRequest;
import com.payments.model.dto.PaymentResponse;
import com.payments.service.PaymentService;
import com.payments.service.IdempotencyService;
import com.payments.util.CorrelationIdUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;

/**
 * Controller for payment operations.
 */
@RestController
@RequestMapping("/api/v1/payments")
@Tag(name = "Payments", description = "Payment processing operations")
@SecurityRequirement(name = "bearerAuth")
public class PaymentController
