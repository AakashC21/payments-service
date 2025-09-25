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

```

