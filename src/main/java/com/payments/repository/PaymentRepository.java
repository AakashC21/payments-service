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

```java:src/main/java/com/payments/repository/UserRepository.java
package com.payments.repository;

import com.payments.model.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repository interface for User entity operations.
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    Optional<User> findByEmail(String email);
    
    boolean existsByEmail(String email);
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
    
    Optional<Order> findByOrderNumber(String orderNumber);
    
    List<Order> findByUserId(Long userId);
    
    List<Order> findByUserIdAndStatus(Long userId, Order.OrderStatus status);
    
    @Query("SELECT o FROM Order o WHERE o.status = :status")
    List<Order> findByStatus(@Param("status") Order.OrderStatus status);
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
    void deleteExpiredKeys(@Param("expiryDate") LocalDateTime expiryDate);
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

```java:src/main/java/com/payments/service/SubscriptionService.java
package com.payments.service;

import com.payments.gateway.AuthorizeNetGateway;
import com.payments.model.dto.SubscriptionRequest;
import com.payments.model.dto.SubscriptionResponse;
import com.payments.model.entity.Subscription;
import com.payments.repository.SubscriptionRepository;
import com.payments.metrics.PaymentMetrics;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Service for subscription management operations.
 */
@Service
@Transactional
public class SubscriptionService {
    
    private static final Logger logger = LoggerFactory.getLogger(SubscriptionService.class);
    
    private final SubscriptionRepository subscriptionRepository;
    private final AuthorizeNetGateway authorizeNetGateway;
    private final PaymentMetrics paymentMetrics;
    
    public SubscriptionService(SubscriptionRepository subscriptionRepository,
                              AuthorizeNetGateway authorizeNetGateway,
                              PaymentMetrics paymentMetrics) {
        this.subscriptionRepository = subscriptionRepository;
        this.authorizeNetGateway = authorizeNetGateway;
        this.paymentMetrics = paymentMetrics;
    }
    
    public SubscriptionResponse createSubscription(SubscriptionRequest request, Long userId, String correlationId) {
        logger.info("Creating subscription for user: {}", userId);
        
        try {
            // Create subscription entity
            Subscription subscription = new Subscription();
            subscription.setUserId(userId);
            subscription.setPlanName(request.getPlanName());
            subscription.setAmount(request.getAmount());
            subscription.setBillingInterval(request.getBillingInterval());
            subscription.setStatus(Subscription.SubscriptionStatus.ACTIVE);
            subscription.setCreatedAt(LocalDateTime.now());
            subscription.setNextBillingDate(LocalDateTime.now().plusDays(request.getBillingInterval()));
            
            // Save to database
            subscription = subscriptionRepository.save(subscription);
            
            // Create in Authorize.Net (mock implementation)
            String authorizeNetSubscriptionId = authorizeNetGateway.createSubscription(subscription);
            subscription.setAuthorizeNetSubscriptionId(authorizeNetSubscriptionId);
            subscription = subscriptionRepository.save(subscription);
            
            paymentMetrics.incrementSubscriptionsCreated();
            
            return convertToResponse(subscription);
            
        } catch (Exception e) {
            logger.error("Failed to create subscription for user: {}", userId, e);
            throw e;
        }
    }
    
    public SubscriptionResponse updateSubscription(Long subscriptionId, SubscriptionRequest request, String correlationId) {
        logger.info("Updating subscription: {}", subscriptionId);
        
        Subscription subscription = subscriptionRepository.findById(subscriptionId)
            .orElseThrow(() -> new RuntimeException("Subscription not found"));
        
        subscription.setPlanName(request.getPlanName());
        subscription.setAmount(request.getAmount());
        subscription.setBillingInterval(request.getBillingInterval());
        subscription.setUpdatedAt(LocalDateTime.now());
        
        subscription = subscriptionRepository.save(subscription);
        
        return convertToResponse(subscription);
    }
    
    public SubscriptionResponse cancelSubscription(Long subscriptionId, String correlationId) {
        logger.info("Cancelling subscription: {}", subscriptionId);
        
        Subscription subscription = subscriptionRepository.findById(subscriptionId)
            .orElseThrow(() -> new RuntimeException("Subscription not found"));
        
        subscription.setStatus(Subscription.SubscriptionStatus.CANCELLED);
        subscription.setUpdatedAt(LocalDateTime.now());
        
        subscription = subscriptionRepository.save(subscription);
        
        paymentMetrics.incrementSubscriptionsCancelled();
        
        return convertToResponse(subscription);
    }
    
    public List<SubscriptionResponse> getUserSubscriptions(Long userId) {
        List<Subscription> subscriptions = subscriptionRepository.findByUserId(userId);
        return subscriptions.stream()
            .map(this::convertToResponse)
            .collect(Collectors.toList());
    }
    
    private SubscriptionResponse convertToResponse(Subscription subscription) {
        SubscriptionResponse response = new SubscriptionResponse();
        response.setId(subscription.getId());
        response.setUserId(subscription.getUserId());
        response.setPlanName(subscription.getPlanName());
        response.setAmount(subscription.getAmount());
        response.setBillingInterval(subscription.getBillingInterval());
        response.setStatus(subscription.getStatus().name());
        response.setNextBillingDate(subscription.getNextBillingDate());
        response.setCreatedAt(subscription.getCreatedAt());
        return response;
    }
}

```

```java:src/main/java/com/payments/service/PaymentService.java
package com.payments.service;

import com.payments.gateway.AuthorizeNetGateway;
import com.payments.model.dto.PaymentRequest;
import com.payments.model.dto.PaymentResponse;
import com.payments.model.entity.Order;
import com.payments.model.entity.Payment;
import com.payments.repository.OrderRepository;
import com.payments.repository.PaymentRepository;
import com.payments.metrics.PaymentMetrics;
import io.micrometer.core.instrument.Timer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * Service for payment processing operations.
 */
@Service
@Transactional
public class PaymentService {
    
    private static final Logger logger = LoggerFactory.getLogger(PaymentService.class);
    
    private final PaymentRepository paymentRepository;
    private final OrderRepository orderRepository;
    private final AuthorizeNetGateway authorizeNetGateway;
    private final PaymentMetrics paymentMetrics;
    
    public PaymentService(PaymentRepository paymentRepository,
                         OrderRepository orderRepository,
                         AuthorizeNetGateway authorizeNetGateway,
                         PaymentMetrics paymentMetrics) {
        this.paymentRepository = paymentRepository;
        this.orderRepository = orderRepository;
        this.authorizeNetGateway = authorizeNetGateway;
        this.paymentMetrics = paymentMetrics;
    }
    
    public PaymentResponse processPurchase(PaymentRequest request, String correlationId) {
        logger.info("Processing purchase for order: {}", request.getOrderNumber());
        
        Timer.Sample sample = Timer.start();
        try {
            // Create or get order
            Order order = createOrGetOrder(request);
            
            // Create payment entity
            Payment payment = new Payment();
            payment.setOrderId(order.getId());
            payment.setUserId(order.getUserId());
            payment.setAmount(request.getAmount());
            payment.setCurrency(request.getCurrency());
            payment.setStatus(Payment.PaymentStatus.PENDING);
            payment.setPaymentMethod(request.getPaymentMethod());
            payment.setCreatedAt(LocalDateTime.now());
            
            payment = paymentRepository.save(payment);
            
            // Process with Authorize.Net (mock implementation)
            String transactionId = authorizeNetGateway.processPurchase(request);
            payment.setAuthorizeNetTransactionId(transactionId);
            payment.setStatus(Payment.PaymentStatus.COMPLETED);
            payment.setProcessedAt(LocalDateTime.now());
            
            payment = paymentRepository.save(payment);
            
            paymentMetrics.incrementPaymentsProcessed();
            
            return convertToResponse(payment);
            
        } catch (Exception e) {
            logger.error("Purchase processing failed for order: {}", request.getOrderNumber(), e);
            throw e;
        } finally {
            sample.stop(paymentMetrics.getPaymentProcessingTime());
        }
    }
    
    public PaymentResponse authorizePayment(PaymentRequest request, String correlationId) {
        logger.info("Authorizing payment for order: {}", request.getOrderNumber());
        
        Order order = createOrGetOrder(request);
        
        Payment payment = new Payment();
        payment.setOrderId(order.getId());
        payment.setUserId(order.getUserId());
        payment.setAmount(request.getAmount());
        payment.setCurrency(request.getCurrency());
        payment.setStatus(Payment.PaymentStatus.AUTHORIZED);
        payment.setPaymentMethod(request.getPaymentMethod());
        payment.setCreatedAt(LocalDateTime.now());
        
        payment = paymentRepository.save(payment);
        
        String transactionId = authorizeNetGateway.authorizePayment(request);
        payment.setAuthorizeNetTransactionId(transactionId);
        payment = paymentRepository.save(payment);
        
        return convertToResponse(payment);
    }
    
    public PaymentResponse capturePayment(String authorizationTransactionId, BigDecimal amount, String correlationId) {
        logger.info("Capturing payment for transaction: {}", authorizationTransactionId);
        
        Payment payment = paymentRepository.findByAuthorizeNetTransactionId(authorizationTransactionId)
            .orElseThrow(() -> new RuntimeException("Payment not found"));
        
        payment.setStatus(Payment.PaymentStatus.COMPLETED);
        payment.setProcessedAt(LocalDateTime.now());
        
        payment = paymentRepository.save(payment);
        
        return convertToResponse(payment);
    }
    
    public PaymentResponse refundPayment(String originalTransactionId, BigDecimal amount, String correlationId) {
        logger.info("Processing refund for transaction: {}", originalTransactionId);
        
        Payment payment = paymentRepository.findByAuthorizeNetTransactionId(originalTransactionId)
            .orElseThrow(() -> new RuntimeException("Payment not found"));
        
        payment.setStatus(Payment.PaymentStatus.REFUNDED);
        payment.setProcessedAt(LocalDateTime.now());
        
        payment = paymentRepository.save(payment);
        
        return convertToResponse(payment);
    }
    
    public PaymentResponse voidPayment(String transactionId, String correlationId) {
        logger.info("Voiding payment for transaction: {}", transactionId);
        
        Payment payment = paymentRepository.findByAuthorizeNetTransactionId(transactionId)
            .orElseThrow(() -> new RuntimeException("Payment not found"));
        
        payment.setStatus(Payment.PaymentStatus.VOIDED);
        payment.setProcessedAt(LocalDateTime.now());
        
        payment = paymentRepository.save(payment);
        
        return convertToResponse(payment);
    }
    
    private Order createOrGetOrder(PaymentRequest request) {
        return orderRepository.findByOrderNumber(request.getOrderNumber())
            .orElseGet(() -> {
                Order order = new Order();
                order.setOrderNumber(request.getOrderNumber());
                order.setUserId(1L); // TODO: Get from security context
                order.setAmount(request.getAmount());
                order.setCurrency(request.getCurrency());
                order.setStatus(Order.OrderStatus.PENDING);
                order.setCreatedAt(LocalDateTime.now());
                return orderRepository.save(order);
            });
    }
    
    private PaymentResponse convertToResponse(Payment payment) {
        PaymentResponse response = new PaymentResponse();
        response.setId(payment.getId());
        response.setTransactionId(payment.getAuthorizeNetTransactionId());
        response.setAmount(payment.getAmount());
        response.setCurrency(payment.getCurrency());
        response.setStatus(payment.getStatus().name());
        response.setPaymentMethod(payment.getPaymentMethod());
        response.setCreatedAt(payment.getCreatedAt());
        response.setProcessedAt(payment.getProcessedAt());
        return response;
    }
}

```

```java:src/main/java/com/payments/service/WebhookService.java
package com.payments.service;

import com.payments.gateway.AuthorizeNetGateway;
import com.payments.model.entity.WebhookEvent;
import com.payments.repository.WebhookEventRepository;
import com.payments.metrics.PaymentMetrics;
import io.micrometer.core.instrument.Timer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Service for webhook event processing.
 */
@Service
@Transactional
public class WebhookService {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookService.class);
    
    private final WebhookEventRepository webhookEventRepository;
    private final AuthorizeNetGateway authorizeNetGateway;
    private final PaymentMetrics paymentMetrics;
    private final RedisTemplate<String, Object> redisTemplate;
    
    public WebhookService(WebhookEventRepository webhookEventRepository,
                         AuthorizeNetGateway authorizeNetGateway,
                         PaymentMetrics paymentMetrics,
                         RedisTemplate<String, Object> redisTemplate) {
        this.webhookEventRepository = webhookEventRepository;
        this.authorizeNetGateway = authorizeNetGateway;
        this.paymentMetrics = paymentMetrics;
        this.redisTemplate = redisTemplate;
    }
    
    public void processWebhookEvent(String payload, String signature, String correlationId) {
        logger.info("Processing webhook event with correlation ID: {}", correlationId);
        paymentMetrics.incrementWebhooksProcessedTotal();
        
        Timer.Sample sample = Timer.start();
        try {
            // Verify signature
            if (!authorizeNetGateway.verifyWebhookSignature(payload, signature)) {
                logger.error("Webhook signature verification failed");
                throw new RuntimeException("Invalid webhook signature");
            }
            
            // Generate event ID
            String eventId = UUID.randomUUID().toString();
            
            // Create webhook event entity
            WebhookEvent webhookEvent = new WebhookEvent();
            webhookEvent.setId(Long.parseLong(eventId.substring(0, 8), 16));
            webhookEvent.setEventType("payment_notification");
            webhookEvent.setPayload(payload);
            webhookEvent.setSignature(signature);
            webhookEvent.setCorrelationId(correlationId);
            webhookEvent.setStatus(WebhookEvent.ProcessingStatus.PENDING);
            webhookEvent.setCreatedAt(LocalDateTime.now());
            
            webhookEvent = webhookEventRepository.save(webhookEvent);
            
            // Queue for async processing
            queueWebhookEvent(webhookEvent);
            
            paymentMetrics.incrementWebhooksProcessedSuccessful();
            logger.info("Webhook event queued successfully: {}", eventId);
            
        } catch (Exception e) {
            paymentMetrics.incrementWebhooksProcessedFailed();
            logger.error("Failed to process webhook event: {}", e.getMessage(), e);
            throw e;
        } finally {
            sample.stop(paymentMetrics.getWebhookProcessingTime());
        }
    }
    
    private void queueWebhookEvent(WebhookEvent webhookEvent) {
        String queueKey = "webhook_events_queue";
        redisTemplate.opsForList().rightPush(queueKey, webhookEvent.getId());
        logger.debug("Webhook event queued: {}", webhookEvent.getId());
    }
    
    public void processQueuedWebhookEvents() {
        String queueKey = "webhook_events_queue";
        
        while (true) {
            Long webhookEventId = (Long) redisTemplate.opsForList().leftPop(queueKey);
            if (webhookEventId == null) {
                break;
            }
            
            try {
                processQueuedWebhookEvent(webhookEventId);
            } catch (Exception e) {
                logger.error("Failed to process queued webhook event: {}", webhookEventId, e);
                handleWebhookProcessingFailure(webhookEventId, e.getMessage());
            }
        }
    }
    
    private void processQueuedWebhookEvent(Long webhookEventId) {
        WebhookEvent webhookEvent = webhookEventRepository.findById(webhookEventId)
            .orElseThrow(() -> new RuntimeException("Webhook event not found"));
        
        webhookEvent.setStatus(WebhookEvent.ProcessingStatus.PROCESSING);
        webhookEventRepository.save(webhookEvent);
        
        try {
            // Parse and process the webhook payload
            processWebhookPayload(webhookEvent.getPayload(), webhookEvent.getEventType());
            
            webhookEvent.setStatus(WebhookEvent.ProcessingStatus.COMPLETED);
            webhookEventRepository.save(webhookEvent);
            
            logger.info("Webhook event processed successfully: {}", webhookEventId);
            
        } catch (Exception e) {
            handleWebhookProcessingFailure(webhookEventId, e.getMessage());
        }
    }
    
    private void processWebhookPayload(String payload, String eventType) {
        logger.info("Processing webhook payload for event type: {}", eventType);
        // TODO: Implement specific webhook payload processing based on event type
    }
    
    private void handleWebhookProcessingFailure(Long webhookEventId, String errorMessage) {
        WebhookEvent webhookEvent = webhookEventRepository.findById(webhookEventId)
            .orElseThrow(() -> new RuntimeException("Webhook event not found"));
        
        webhookEvent.setRetryCount(webhookEvent.getRetryCount() + 1);
        webhookEvent.setErrorMessage(errorMessage);
        
        if (webhookEvent.getRetryCount() < 3) {
            webhookEvent.setStatus(WebhookEvent.ProcessingStatus.RETRYING);
        } else {
            webhookEvent.setStatus(WebhookEvent.ProcessingStatus.FAILED);
        }
        
        webhookEventRepository.save(webhookEvent);
        
        logger.warn("Webhook processing failed for event: {}, retry count: {}", 
            webhookEventId, webhookEvent.getRetryCount());
    }
}

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
```

```

