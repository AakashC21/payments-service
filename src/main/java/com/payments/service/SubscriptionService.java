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
