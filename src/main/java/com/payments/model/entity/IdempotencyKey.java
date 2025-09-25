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
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}
