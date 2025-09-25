package com.payments.repository;

import com.payments.model.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repository interface for User entity operations.
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    Optional<User> findByEmail(String email);
    
    boolean existsByEmail(String email);
    
    /**
     * Finds active users by email.
     * 
     * @param email Email address to search for
     * @return Optional containing the active user if found
     */
    @Query("SELECT u FROM User u WHERE u.email = :email AND u.status = 'ACTIVE'")
    Optional<User> findActiveUserByEmail(@Param("email") String email);
}

```

```java:src/main/java/com/payments/repository/OrderRepository.java
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
    
    /**
     * Finds an order by order number.
     * 
     * @param orderNumber Order number to search for
     * @return Optional containing the order if found
     */
    Optional<Order> findByOrderNumber(String orderNumber);
    
    /**
     * Finds all orders for a specific user.
     * 
     * @param userId User ID to filter by
     * @return List of orders for the user
     */
    List<Order> findByUserId(Long userId);
    
    /**
     * Finds orders by status.
     * 
     * @param status Order status to filter by
     * @return List of orders with the specified status
     */
    List<Order> findByStatus(Order.OrderStatus status);
    
    /**
     * Finds orders for a user with specific status.
     * 
     * @param userId User ID to filter by
     * @param status Order status to filter by
     * @return List of orders matching both criteria
     */
    List<Order> findByUserIdAndStatus(Long userId, Order.OrderStatus status);
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
    
    /**
     * Finds a payment by Authorize.Net transaction ID.
     * 
     * @param authorizeNetTransactionId Transaction ID to search for
     * @return Optional containing the payment if found
     */
    Optional<Payment> findByAuthorizeNetTransactionId(String authorizeNetTransactionId);
    
    /**
     * Finds all payments for a specific order.
     * 
     * @param orderId Order ID to filter by
     * @return List of payments for the order
     */
    List<Payment> findByOrderId(Long orderId);
    
    /**
     * Finds payments by status.
     * 
     * @param status Payment status to filter by
     * @return List of payments with the specified status
     */
    List<Payment> findByStatus(Payment.PaymentStatus status);
    
    /**
     * Finds payments by type and status.
     * 
     * @param type Payment type to filter by
     * @param status Payment status to filter by
     * @return List of payments matching both criteria
     */
    List<Payment> findByTypeAndStatus(Payment.PaymentType type, Payment.PaymentStatus status);
    
    /**
     * Finds payments by correlation ID.
     * 
     * @param correlationId Correlation ID to search for
     * @return List of payments with the specified correlation ID
     */
    List<Payment> findByCorrelationId(String correlationId);
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
    
    /**
     * Finds a subscription by Authorize.Net subscription ID.
     * 
     * @param authorizeNetSubscriptionId Subscription ID to search for
     * @return Optional containing the subscription if found
     */
    Optional<Subscription> findByAuthorizeNetSubscriptionId(String authorizeNetSubscriptionId);
    
    /**
     * Finds all subscriptions for a specific user.
     * 
     * @param userId User ID to filter by
     * @return List of subscriptions for the user
     */
    List<Subscription> findByUserId(Long userId);
    
    /**
     * Finds subscriptions by status.
     * 
     * @param status Subscription status to filter by
     * @return List of subscriptions with the specified status
     */
    List<Subscription> findByStatus(Subscription.SubscriptionStatus status);
    
    /**
     * Finds active subscriptions for a user.
     * 
     * @param userId User ID to filter by
     * @return List of active subscriptions for the user
     */
    @Query("SELECT s FROM Subscription s WHERE s.userId = :userId AND s.status = 'ACTIVE'")
    List<Subscription> findActiveSubscriptionsByUserId(@Param("userId") Long userId);
    
    /**
     * Finds subscriptions due for billing.
     * 
     * @param currentDate Current date to compare against
     * @return List of subscriptions due for billing
     */
    @Query("SELECT s FROM Subscription s WHERE s.nextBillingDate <= :currentDate AND s.status = 'ACTIVE'")
    List<Subscription> findSubscriptionsDueForBilling(@Param("currentDate") LocalDateTime currentDate);
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
    
    /**
     * Finds an idempotency key by key value.
     * 
     * @param key Key value to search for
     * @return Optional containing the idempotency key if found
     */
    Optional<IdempotencyKey> findByKey(String key);
    
    /**
     * Finds a non-expired idempotency key.
     * 
     * @param key Key value to search for
     * @param currentTime Current time for expiration check
     * @return Optional containing the non-expired idempotency key if found
     */
    @Query("SELECT ik FROM IdempotencyKey ik WHERE ik.key = :key AND ik.expiresAt > :currentTime")
    Optional<IdempotencyKey> findByKeyAndNotExpired(@Param("key") String key, @Param("currentTime") LocalDateTime currentTime);
    
    /**
     * Deletes expired idempotency keys.
     * 
     * @param currentTime Current time for expiration check
     * @return Number of deleted keys
     */
    @Modifying
    @Query("DELETE FROM IdempotencyKey ik WHERE ik.expiresAt <= :currentTime")
    int deleteExpiredKeys(@Param("currentTime") LocalDateTime currentTime);
    
    /**
     * Finds idempotency keys by endpoint.
     * 
     * @param endpoint Endpoint to filter by
     * @return List of idempotency keys for the endpoint
     */
    @Query("SELECT ik FROM IdempotencyKey ik WHERE ik.endpoint = :endpoint")
    java.util.List<IdempotencyKey> findByEndpoint(@Param("endpoint") String endpoint);
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
import java.util.Optional;

/**
 * Repository interface for WebhookEvent entity operations.
 */
@Repository
public interface WebhookEventRepository extends JpaRepository<WebhookEvent, Long> {
    
    /**
     * Finds a webhook event by event ID.
     * 
     * @param eventId Event ID to search for
     * @return Optional containing the webhook event if found
     */
    Optional<WebhookEvent> findByEventId(String eventId);
    
    /**
     * Finds webhook events by status.
     * 
     * @param status Processing status to filter by
     * @return List of webhook events with the specified status
     */
    List<WebhookEvent> findByStatus(WebhookEvent.ProcessingStatus status);
    
    /**
     * Finds webhook events by type.
     * 
     * @param eventType Event type to filter by
     * @return List of webhook events of the specified type
     */
    List<WebhookEvent> findByEventType(String eventType);
    
    /**
     * Finds webhook events that need retry.
     * 
     * @param maxRetries Maximum number of retries allowed
     * @param currentTime Current time for retry delay
     * @return List of webhook events that can be retried
     */
    @Query("SELECT we FROM WebhookEvent we WHERE we.status = 'FAILED' AND we.retryCount < :maxRetries AND we.createdAt <= :currentTime")
    List<WebhookEvent> findEventsForRetry(@Param("maxRetries") int maxRetries, @Param("currentTime") LocalDateTime currentTime);
    
    /**
     * Finds webhook events by correlation ID.
     * 
     * @param correlationId Correlation ID to search for
     * @return List of webhook events with the specified correlation ID
     */
    List<WebhookEvent> findByCorrelationId(String correlationId);
}

```

Now let me create the metrics class:

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

Now let me create the gateway interface:

```java:src/main/java/com/payments/gateway/AuthorizeNetGateway.java
package com.payments.gateway;

import com.payments.model.dto.PaymentRequest;
import com.payments.model.dto.SubscriptionRequest;
import com.payments.model.entity.Payment;
import com.payments.model.entity.Subscription;

/**
 * Gateway interface for Authorize.Net payment processing.
 * 
 * Key features:
 * - Payment processing operations
 * - Subscription management
 * - Transaction lifecycle management
 * - Error handling and response mapping
 */
public interface AuthorizeNetGateway {
    
    /**
     * Processes a purchase payment (auth + capture in one step).
     * 
     * @param paymentRequest Payment request details
     * @param correlationId Correlation ID for tracing
     * @return Payment result with transaction details
     */
    PaymentResult processPurchase(PaymentRequest paymentRequest, String correlationId);
    
    /**
     * Authorizes a payment (without capturing).
     * 
     * @param paymentRequest Payment request details
     * @param correlationId Correlation ID for tracing
     * @return Payment result with authorization details
     */
    PaymentResult authorizePayment(PaymentRequest paymentRequest, String correlationId);
    
    /**
     * Captures a previously authorized payment.
     * 
     * @param authorizationTransactionId Original authorization transaction ID
     * @param amount Amount to capture (can be partial)
     * @param correlationId Correlation ID for tracing
     * @return Payment result with capture details
     */
    PaymentResult capturePayment(String authorizationTransactionId, java.math.BigDecimal amount, String correlationId);
    
    /**
     * Refunds a payment.
     * 
     * @param originalTransactionId Original transaction ID to refund
     * @param amount Amount to refund (can be partial)
     * @param correlationId Correlation ID for tracing
     * @return Payment result with refund details
     */
    PaymentResult refundPayment(String originalTransactionId, java.math.BigDecimal amount, String correlationId);
    
    /**
     * Voids a payment (cancels before capture).
     * 
     * @param transactionId Transaction ID to void
     * @param correlationId Correlation ID for tracing
     * @return Payment result with void details
     */
    PaymentResult voidPayment(String transactionId, String correlationId);
    
    /**
     * Creates a subscription.
     * 
     * @param subscriptionRequest Subscription request details
     * @param correlationId Correlation ID for tracing
     * @return Subscription result with subscription details
     */
    SubscriptionResult createSubscription(SubscriptionRequest subscriptionRequest, String correlationId);
    
    /**
     * Updates a subscription.
     * 
     * @param subscriptionId Subscription ID to update
     * @param subscriptionRequest Updated subscription details
     * @param correlationId Correlation ID for tracing
     * @return Subscription result with updated details
     */
    SubscriptionResult updateSubscription(String subscriptionId, SubscriptionRequest subscriptionRequest, String correlationId);
    
    /**
     * Cancels a subscription.
     * 
     * @param subscriptionId Subscription ID to cancel
     * @param correlationId Correlation ID for tracing
     * @return Subscription result with cancellation details
     */
    SubscriptionResult cancelSubscription(String subscriptionId, String correlationId);
    
    /**
     * Gets subscription details.
     * 
     * @param subscriptionId Subscription ID to retrieve
     * @param correlationId Correlation ID for tracing
     * @return Subscription result with subscription details
     */
    SubscriptionResult getSubscription(String subscriptionId, String correlationId);
    
    /**
     * Verifies webhook signature.
     * 
     * @param payload Webhook payload
     * @param signature Webhook signature
     * @return true if signature is valid, false otherwise
     */
    boolean verifyWebhookSignature(String payload, String signature);
    
    /**
     * Result class for payment operations.
     */
    class PaymentResult {
        private boolean success;
        private String transactionId;
        private String responseCode;
        private String responseMessage;
        private String rawResponse;
        private Payment.PaymentStatus status;
        
        // Constructors
        public PaymentResult() {}
        
        public PaymentResult(boolean success, String transactionId, String responseCode, String responseMessage) {
            this.success = success;
            this.transactionId = transactionId;
            this.responseCode = responseCode;
            this.responseMessage = responseMessage;
        }
        
        // Getters and Setters
        public boolean isSuccess() { return success; }
        public void setSuccess(boolean success) { this.success = success; }
        
        public String getTransactionId() { return transactionId; }
        public void setTransactionId(String transactionId) { this.transactionId = transactionId; }
        
        public String getResponseCode() { return responseCode; }
        public void setResponseCode(String responseCode) { this.responseCode = responseCode; }
        
        public String getResponseMessage() { return responseMessage; }
        public void setResponseMessage(String responseMessage) { this.responseMessage = responseMessage; }
        
        public String getRawResponse() { return rawResponse; }
        public void setRawResponse(String rawResponse) { this.rawResponse = rawResponse; }
        
        public Payment.PaymentStatus getStatus() { return status; }
        public void setStatus(Payment.PaymentStatus status) { this.status = status; }
    }
    
    /**
     * Result class for subscription operations.
     */
    class SubscriptionResult {
        private boolean success;
        private String subscriptionId;
        private String responseCode;
        private String responseMessage;
        private String rawResponse;
        private Subscription.SubscriptionStatus status;
        
        // Constructors
        public SubscriptionResult() {}
        
        public SubscriptionResult(boolean success, String subscriptionId, String responseCode, String responseMessage) {
            this.success = success;
            this.subscriptionId = subscriptionId;
            this.responseCode = responseCode;
            this.responseMessage = responseMessage;
        }
        
        // Getters and Setters
        public boolean isSuccess() { return success; }
        public void setSuccess(boolean success) { this.success = success; }
        
        public String getSubscriptionId() { return subscriptionId; }
        public void setSubscriptionId(String subscriptionId) { this.subscriptionId = subscriptionId; }
        
        public String getResponseCode() { return responseCode; }
        public void setResponseCode(String responseCode) { this.responseCode = responseCode; }
        
        public String getResponseMessage() { return responseMessage; }
        public void setResponseMessage(String responseMessage) { this.responseMessage = responseMessage; }
        
        public String getRawResponse() { return rawResponse; }
        public void setRawResponse(String rawResponse) { this.rawResponse = rawResponse; }
        
        public Subscription.SubscriptionStatus getStatus() { return status; }
        public void setStatus(Subscription.SubscriptionStatus status) { this.status = status; }
    }
}

```

Now let me create the service classes. First, let me create the IdempotencyService:

```java:src/main/java/com/payments/service/IdempotencyService.java
package com.payments.service;

import com.payments.model.entity.IdempotencyKey;
import com.payments.repository.IdempotencyKeyRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Service for handling idempotency key operations.
 * 
 * Key features:
 * - Dual-layer caching (Redis + PostgreSQL)
 * - Request/response caching
 * - Expiration management
 * - Conflict detection
 */
@Service
public class IdempotencyService {
    
    private static final Logger logger = LoggerFactory.getLogger(IdempotencyService.class);
    
    private final IdempotencyKeyRepository idempotencyKeyRepository;
    private final RedisTemplate<String, Object> redisTemplate;
    
    @Value("${app.idempotency.ttl-hours:24}")
    private int ttlHours;
    
    @Value("${app.idempotency.redis-ttl-minutes:60}")
    private int redisTtlMinutes;
    
    public IdempotencyService(IdempotencyKeyRepository idempotencyKeyRepository, 
                             RedisTemplate<String, Object> redisTemplate) {
        this.idempotencyKeyRepository = idempotencyKeyRepository;
        this.redisTemplate = redisTemplate;
    }
    
    /**
     * Checks if a request is idempotent and returns cached response if available.
     * 
     * @param idempotencyKey Idempotency key from request header
     * @param endpoint API endpoint being called
     * @param correlationId Correlation ID for tracing
     * @return Optional containing cached response if request is idempotent
     */
    public Optional<String> checkIdempotency(String idempotencyKey, String endpoint, String correlationId) {
        if (idempotencyKey == null || idempotencyKey.isEmpty()) {
            return Optional.empty();
        }
        
        // First check Redis cache for fast lookup
        String redisKey = "idempotency:" + idempotencyKey;
        String cachedResponse = (String) redisTemplate.opsForValue().get(redisKey);
        
        if (cachedResponse != null) {
            logger.debug("Found idempotent response in Redis cache for key: {}", idempotencyKey);
            return Optional.of(cachedResponse);
        }
        
        // Check PostgreSQL for persistent storage
        Optional<IdempotencyKey> existingKey = idempotencyKeyRepository
            .findByKeyAndNotExpired(idempotencyKey, LocalDateTime.now());
        
        if (existingKey.isPresent()) {
            IdempotencyKey key = existingKey.get();
            String response = key.getResponseBody();
            
            // Cache in Redis for future fast access
            if (response != null) {
                redisTemplate.opsForValue().set(redisKey, response, 
                    java.time.Duration.ofMinutes(redisTtlMinutes));
            }
            
            logger.debug("Found idempotent response in database for key: {}", idempotencyKey);
            return Optional.of(response);
        }
        
        return Optional.empty();
    }
    
    /**
     * Stores the request and response for idempotency checking.
     * 
     * @param idempotencyKey Idempotency key from request header
     * @param endpoint API endpoint being called
     * @param requestBody Request body for duplicate detection
     * @param responseBody Response body to cache
     * @param correlationId Correlation ID for tracing
     */
    public void storeIdempotencyKey(String idempotencyKey, String endpoint, String requestBody, 
                                   String responseBody, String correlationId) {
        if (idempotencyKey == null || idempotencyKey.isEmpty()) {
            return;
        }
        
        LocalDateTime expiresAt = LocalDateTime.now().plusHours(ttlHours);
        
        // Store in PostgreSQL for persistence
        IdempotencyKey key = new IdempotencyKey(idempotencyKey, requestBody, correlationId, endpoint, expiresAt);
        key.setResponseBody(responseBody);
        idempotencyKeyRepository.save(key);
        
        // Store in Redis for fast access
        String redisKey = "idempotency:" + idempotencyKey;
        redisTemplate.opsForValue().set(redisKey, responseBody, 
            java.time.Duration.ofMinutes(redisTtlMinutes));
        
        logger.debug("Stored idempotency key: {} for endpoint: {}", idempotencyKey, endpoint);
    }
    
    /**
     * Checks if a request body matches the stored idempotency key.
     * 
     * @param idempotencyKey Idempotency key from request header
     * @param requestBody Current request body
     * @return true if request body matches, false otherwise
     */
    public boolean isRequestBodyMatching(String idempotencyKey, String requestBody) {
        if (idempotencyKey == null || idempotencyKey.isEmpty()) {
            return false;
        }
        
        Optional<IdempotencyKey> existingKey = idempotencyKeyRepository
            .findByKeyAndNotExpired(idempotencyKey, LocalDateTime.now());
        
        if (existingKey.isPresent()) {
            String storedRequestBody = existingKey.get().getRequestBody();
            return requestBody.equals(storedRequestBody);
        }
        
        return false;
    }
    
    /**
     * Cleans up expired idempotency keys.
     */
    public void cleanupExpiredKeys() {
        int deletedCount = idempotencyKeyRepository.deleteExpiredKeys(LocalDateTime.now());
        if (deletedCount > 0) {
            logger.info("Cleaned up {} expired idempotency keys", deletedCount);
        }
    }
}

```

Now let me create the remaining service classes. Due to length constraints, I'll create the key service files:

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

import java.util.Optional;

/**
 * Service for user authentication operations.
 * 
 * Key features:
 * - User login validation
 * - JWT token generation
 * - Password verification
 * - User status checking
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
    
    /**
     * Authenticates a user and generates JWT token.
     * 
     * @param loginRequest Login credentials
     * @return Login response with JWT token
     * @throws RuntimeException if authentication fails
     */
    public LoginResponse authenticateUser(LoginRequest loginRequest) {
        logger.info("Attempting to authenticate user: {}", loginRequest.getEmail());
        
        // Find user by email
        Optional<User> userOpt = userRepository.findActiveUserByEmail(loginRequest.getEmail());
        if (userOpt.isEmpty()) {
            logger.warn("Authentication failed: User not found or inactive: {}", loginRequest.getEmail());
            throw new RuntimeException("Invalid credentials");
        }
        
        User user = userOpt.get();
        
        // Verify password
        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPasswordHash())) {
            logger.warn("Authentication failed: Invalid password for user: {}", loginRequest.getEmail());
            throw new RuntimeException("Invalid credentials");
        }
        
        // Generate JWT token
        String token = jwtUtil.generateToken(user.getId(), user.getEmail(), user.getFirstName(), user.getLastName());
        
        // Create user info
        LoginResponse.UserInfo userInfo = new LoginResponse.UserInfo(
            user.getId(), 
            user.getEmail(), 
            user.getFirstName(), 
            user.getLastName()
        );
        
        // Create login response
        LoginResponse response = new LoginResponse(token, (long) jwtUtil.getExpirationTime(), userInfo);
        
        logger.info("User authenticated successfully: {}", user.getEmail());
        return response;
    }
    
    /**
     * Creates a new user (for testing purposes).
     * 
     * @param email User email
     * @param password User password
     * @param firstName User first name
     * @param lastName User last name
     * @return Created user
     */
    public User createUser(String email, String password, String firstName, String lastName) {
        logger.info("Creating new user: {}", email);
        
        // Check if user already exists
        if (userRepository.existsByEmail(email)) {
            throw new RuntimeException("User with email " + email + " already exists");
        }
        
        // Hash password
        String passwordHash = passwordEncoder.encode(password);
        
        // Create user
        User user = new User(email, passwordHash, firstName, lastName);
        user = userRepository.save(user);
        
        logger.info("User created successfully: {}", email);
        return user;
    }
}

```

Let me continue with the remaining critical files. I'll create the configuration files and application properties:

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

Now let me create the missing gateway interface:

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

Now let me create the missing service classes:

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

import java.util.Optional;

/**
 * Service for user authentication operations.
 * 
 * Key features:
 * - User login validation
 * - JWT token generation
 * - Password verification
 * - User status checking
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
    
    /**
     * Authenticates a user and generates JWT token.
     * 
     * @param loginRequest Login credentials
     * @return Login response with JWT token
     * @throws RuntimeException if authentication fails
     */
    public LoginResponse authenticateUser(LoginRequest loginRequest) {
        logger.info("Authenticating user: {}", loginRequest.getEmail());
        
        // Find user by email
        Optional<User> userOpt = userRepository.findActiveUserByEmail(loginRequest.getEmail());
        if (userOpt.isEmpty()) {
            logger.warn("Authentication failed: User not found or inactive: {}", loginRequest.getEmail());
            throw new RuntimeException("Invalid credentials");
        }
        
        User user = userOpt.get();
        
        // Verify password
        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPasswordHash())) {
            logger.warn("Authentication failed: Invalid password for user: {}", loginRequest.getEmail());
            throw new RuntimeException("Invalid credentials");
        }
        
        // Generate JWT token
        String token = jwtUtil.generateToken(user.getId(), user.getEmail(), user.getFirstName(), user.getLastName());
        
        // Create user info
        LoginResponse.UserInfo userInfo = new LoginResponse.UserInfo(
            user.getId(), 
            user.getEmail(), 
            user.getFirstName(), 
            user.getLastName()
        );
        
        // Create login response
        LoginResponse response = new LoginResponse(token, (long) jwtUtil.getExpirationTime(), userInfo);
        
        logger.info("User authenticated successfully: {}", user.getEmail());
        return response;
    }
    
    /**
     * Creates a new user (for testing purposes).
     * 
     * @param email User email
     * @param password User password
     * @param firstName User first name
     * @param lastName User last name
     * @return Created user
     */
    public User createUser(String email, String password, String firstName, String lastName) {
        logger.info("Creating new user: {}", email);
        
        // Check if user already exists
        if (userRepository.existsByEmail(email)) {
            throw new RuntimeException("User with email " + email + " already exists");
        }
        
        // Hash password
        String passwordHash = passwordEncoder.encode(password);
        
        // Create user
        User user = new User(email, passwordHash, firstName, lastName);
        user = userRepository.save(user);
        
        logger.info("User created successfully: {}", email);
        return user;
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

Now let me create the missing controller files:

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
```

```

