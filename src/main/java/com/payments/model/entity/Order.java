package com.payments.model.entity;

import jakarta.persistence.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Order entity representing a customer order that can have multiple payments.
 * 
 * Key features:
 * - One-to-many relationship with payments
 * - Many-to-one relationship with user
 * - Order status tracking
 * - Currency support
 */
@Entity
@Table(name = "orders", indexes = {
    @Index(name = "idx_order_user_id", columnList = "userId"),
    @Index(name = "idx_order_status", columnList = "status"),
    @Index(name = "idx_order_created_at", columnList = "createdAt"),
    @Index(name = "idx_order_order_number", columnList = "orderNumber", unique = true)
})
@EntityListeners(AuditingEntityListener.class)
public class Order {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, unique = true, length = 50)
    private String orderNumber;
    
    @Column(nullable = false)
    private Long userId;
    
    @Column(nullable = false, precision = 10, scale = 2)
    private BigDecimal totalAmount;
    
    @Column(length = 3)
    private String currency = "USD";
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private OrderStatus status = OrderStatus.PENDING;
    
    @Column(length = 500)
    private String description;
    
    @Column(length = 1000)
    private String metadata;
    
    @CreatedDate
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;
    
    @LastModifiedDate
    private LocalDateTime updatedAt;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "userId", insertable = false, updatable = false)
    private User user;
    
    @OneToMany(mappedBy = "order", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Payment> payments = new ArrayList<>();
    
    // Constructors
    public Order() {}
    
    public Order(String orderNumber, Long userId, BigDecimal totalAmount, String description) {
        this.orderNumber = orderNumber;
        this.userId = userId;
        this.totalAmount = totalAmount;
        this.description = description;
    }
    
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getOrderNumber() { return orderNumber; }
    public void setOrderNumber(String orderNumber) { this.orderNumber = orderNumber; }
    
    public Long getUserId() { return userId; }
    public void setUserId(Long userId) { this.userId = userId; }
    
    public BigDecimal getTotalAmount() { return totalAmount; }
    public void setTotalAmount(BigDecimal totalAmount) { this.totalAmount = totalAmount; }
    
    public String getCurrency() { return currency; }
    public void setCurrency(String currency) { this.currency = currency; }
    
    public OrderStatus getStatus() { return status; }
    public void setStatus(OrderStatus status) { this.status = status; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public String getMetadata() { return metadata; }
    public void setMetadata(String metadata) { this.metadata = metadata; }
    
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    
    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }
    
    public User getUser() { return user; }
    public void setUser(User user) { this.user = user; }
    
    public List<Payment> getPayments() { return payments; }
    public void setPayments(List<Payment> payments) { this.payments = payments; }
    
    // Enum for order status
    public enum OrderStatus {
        PENDING, PAID, PARTIALLY_PAID, REFUNDED, CANCELLED, FAILED
    }
}
```

```java:src/main/java/com/payments/model/entity/Payment.java
package com.payments.model.entity;

import jakarta.persistence.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * Payment entity representing individual payment transactions.
 * 
 * Key features:
 * - Links to orders and subscriptions
 * - Payment status tracking
 * - Authorize.Net transaction ID storage
 * - Support for partial payments and refunds
 */
@Entity
@Table(name = "payments", indexes = {
    @Index(name = "idx_payment_order_id", columnList = "orderId"),
    @Index(name = "idx_payment_subscription_id", columnList = "subscriptionId"),
    @Index(name = "idx_payment_status", columnList = "status"),
    @Index(name = "idx_payment_auth_net_id", columnList = "authorizeNetTransactionId"),
    @Index(name = "idx_payment_created_at", columnList = "createdAt")
})
@EntityListeners(AuditingEntityListener.class)
public class Payment {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false)
    private Long orderId;
    
    @Column
    private Long subscriptionId;
    
    @Column(nullable = false, precision = 10, scale = 2)
    private BigDecimal amount;
    
    @Column(length = 3)
    private String currency = "USD";
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private PaymentType type;
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private PaymentStatus status;
    
    @Column(length = 255)
    private String authorizeNetTransactionId;
    
    @Column(length = 1000)
    private String authorizeNetResponse;
    
    @Column(length = 500)
    private String failureReason;
    
    @Column(length = 100)
    private String correlationId;
    
    @Column(length = 100)
    private String idempotencyKey;
    
    @CreatedDate
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;
    
    @LastModifiedDate
    private LocalDateTime updatedAt;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "orderId", insertable = false, updatable = false)
    private Order order;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "subscriptionId", insertable = false, updatable = false)
    private Subscription subscription;
    
    // Constructors
    public Payment() {}
    
    public Payment(Long orderId, BigDecimal amount, PaymentType type, PaymentStatus status) {
        this.orderId = orderId;
        this.amount = amount;
        this.type = type;
        this.status = status;
    }
    
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public Long getOrderId() { return orderId; }
    public void setOrderId(Long orderId) { this.orderId = orderId; }
    
    public Long getSubscriptionId() { return subscriptionId; }
    public void setSubscriptionId(Long subscriptionId) { this.subscriptionId = subscriptionId; }
    
    public BigDecimal getAmount() { return amount; }
    public void setAmount(BigDecimal amount) { this.amount = amount; }
    
    public String getCurrency() { return currency; }
    public void setCurrency(String currency) { this.currency = currency; }
    
    public PaymentType getType() { return type; }
    public void setType(PaymentType type) { this.type = type; }
    
    public PaymentStatus getStatus() { return status; }
    public void setStatus(PaymentStatus status) { this.status = status; }
    
    public String getAuthorizeNetTransactionId() { return authorizeNetTransactionId; }
    public void setAuthorizeNetTransactionId(String authorizeNetTransactionId) { this.authorizeNetTransactionId = authorizeNetTransactionId; }
    
    public String getAuthorizeNetResponse() { return authorizeNetResponse; }
    public void setAuthorizeNetResponse(String authorizeNetResponse) { this.authorizeNetResponse = authorizeNetResponse; }
    
    public String getFailureReason() { return failureReason; }
    public void setFailureReason(String failureReason) { this.failureReason = failureReason; }
    
    public String getCorrelationId() { return correlationId; }
    public void setCorrelationId(String correlationId) { this.correlationId = correlationId; }
    
    public String getIdempotencyKey() { return idempotencyKey; }
    public void setIdempotencyKey(String idempotencyKey) { this.idempotencyKey = idempotencyKey; }
    
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    
    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }
    
    public Order getOrder() { return order; }
    public void setOrder(Order order) { this.order = order; }
    
    public Subscription getSubscription() { return subscription; }
    public void setSubscription(Subscription subscription) { this.subscription = subscription; }
    
    // Enums for payment types and statuses
    public enum PaymentType {
        PURCHASE, AUTHORIZE, CAPTURE, REFUND, VOID
    }
    
    public enum PaymentStatus {
        PENDING, AUTHORIZED, CAPTURED, REFUNDED, VOIDED, FAILED, DECLINED
    }
}
```

```java:src/main/java/com/payments/model/entity/Subscription.java
package com.payments.model.entity;

import jakarta.persistence.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * Subscription entity for recurring billing.
 * 
 * Key features:
 * - Recurring payment scheduling
 * - Subscription status management
 * - Authorize.Net subscription ID storage
 * - Trial period support
 */
@Entity
@Table(name = "subscriptions", indexes = {
    @Index(name = "idx_subscription_user_id", columnList = "userId"),
    @Index(name = "idx_subscription_status", columnList = "status"),
    @Index(name = "idx_subscription_auth_net_id", columnList = "authorizeNetSubscriptionId"),
    @Index(name = "idx_subscription_next_billing", columnList = "nextBillingDate")
})
@EntityListeners(AuditingEntityListener.class)
public class Subscription {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false)
    private Long userId;
    
    @Column(nullable = false, precision = 10, scale = 2)
    private BigDecimal amount;
    
    @Column(length = 3)
    private String currency = "USD";
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private SubscriptionStatus status = SubscriptionStatus.ACTIVE;
    
    @Column(length = 50)
    private String authorizeNetSubscriptionId;
    
    @Column(nullable = false)
    private LocalDateTime nextBillingDate;
    
    @Column
    private Integer billingIntervalDays = 30;
    
    @Column(length = 500)
    private String description;
    
    @Column(length = 1000)
    private String metadata;
    
    @Column
    private LocalDateTime trialEndDate;
    
    @CreatedDate
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;
    
    @LastModifiedDate
    private LocalDateTime updatedAt;
    
    // Constructors
    public Subscription() {}
    
    public Subscription(Long userId, BigDecimal amount, LocalDateTime nextBillingDate, String description) {
        this.userId = userId;
        this.amount = amount;
        this.nextBillingDate = nextBillingDate;
        this.description = description;
    }
    
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public Long getUserId() { return userId; }
    public void setUserId(Long userId) { this.userId = userId; }
    
    public BigDecimal getAmount() { return amount; }
    public void setAmount(BigDecimal amount) { this.amount = amount; }
    
    public String getCurrency() { return currency; }
    public void setCurrency(String currency) { this.currency = currency; }
    
    public SubscriptionStatus getStatus() { return status; }
    public void setStatus(SubscriptionStatus status) { this.status = status; }
    
    public String getAuthorizeNetSubscriptionId() { return authorizeNetSubscriptionId; }
    public void setAuthorizeNetSubscriptionId(String authorizeNetSubscriptionId) { this.authorizeNetSubscriptionId = authorizeNetSubscriptionId; }
    
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
    
    // Enum for subscription status
    public enum SubscriptionStatus {
        ACTIVE, PAUSED, CANCELLED, EXPIRED, FAILED
    }
}
```

```java:src/main/java/com/payments/model/entity/IdempotencyKey.java
package com.payments.model.entity;

import jakarta.persistence.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

/**
 * Idempotency key entity for preventing duplicate operations.
 * 
 * Key features:
 * - Unique constraint on key value
 * - Request/response caching
 * - TTL-based expiration
 * - Correlation ID tracking
 */
@Entity
@Table(name = "idempotency_keys", indexes = {
    @Index(name = "idx_idempotency_key", columnList = "key", unique = true),
    @Index(name = "idx_idempotency_expires_at", columnList = "expiresAt")
})
@EntityListeners(AuditingEntityListener.class)
public class IdempotencyKey {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, unique = true, length = 255)
    private String key;
    
    @Column(nullable = false, columnDefinition = "TEXT")
    private String requestBody;
    
    @Column(columnDefinition = "TEXT")
    private String responseBody;
    
    @Column(length = 100)
    private String correlationId;
    
    @Column(length = 100)
    private String endpoint;
    
    @Column(nullable = false)
    private LocalDateTime expiresAt;
    
    @CreatedDate
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;
    
    // Constructors
    public IdempotencyKey() {}
    
    public IdempotencyKey(String key, String requestBody, String correlationId, String endpoint, LocalDateTime expiresAt) {
        this.key = key;
        this.requestBody = requestBody;
        this.correlationId = correlationId;
        this.endpoint = endpoint;
        this.expiresAt = expiresAt;
    }
    
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getKey() { return key; }
    public void setKey(String key) { this.key = key; }
    
    public String getRequestBody() { return requestBody; }
    public void setRequestBody(String requestBody) { this.requestBody = requestBody; }
    
    public String getResponseBody() { return responseBody; }
    public void setResponseBody(String responseBody) { this.responseBody = responseBody; }
    
    public String getCorrelationId() { return correlationId; }
    public void setCorrelationId(String correlationId) { this.correlationId = correlationId; }
    
    public String getEndpoint() { return endpoint; }
    public void setEndpoint(String endpoint) { this.endpoint = endpoint; }
    
    public LocalDateTime getExpiresAt() { return expiresAt; }
    public void setExpiresAt(LocalDateTime expiresAt) { this.expiresAt = expiresAt; }
    
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = create
