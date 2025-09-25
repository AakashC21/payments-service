package com.payments.controller;

import com.payments.model.dto.ApiResponse;
import com.payments.model.dto.SubscriptionRequest;
import com.payments.model.dto.SubscriptionResponse;
import com.payments.service.SubscriptionService;
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

import java.util.List;

/**
 * Controller for subscription operations.
 * 
 * Key features:
 * - Subscription CRUD operations
 * - JWT authentication
 * - Correlation ID tracking
 */
@RestController
@RequestMapping("/api/v1/subscriptions")
@Tag(name = "Subscriptions", description = "Subscription management operations")
@SecurityRequirement(name = "bearerAuth")
public class SubscriptionController {
    
    private static final Logger logger = LoggerFactory.getLogger(SubscriptionController.class);
    
    private final SubscriptionService subscriptionService;
    
    public SubscriptionController(SubscriptionService subscriptionService) {
        this.subscriptionService = subscriptionService;
    }
    
    /**
     * Creates a new subscription.
     */
    @PostMapping
    @Operation(summary = "Create subscription", description = "Creates a new recurring subscription")
    public ResponseEntity<ApiResponse<SubscriptionResponse>> createSubscription(
            @Valid @RequestBody SubscriptionRequest request,
            HttpServletRequest httpRequest) {
        
        String correlationId = CorrelationIdUtil.getCorrelationId();
        Long userId = (Long) httpRequest.getAttribute("userId");
        
        logger.info("Creating subscription for user: {}", userId);
        
        try {
            SubscriptionResponse response = subscriptionService.createSubscription(request, userId, correlationId);
            ApiResponse<SubscriptionResponse> apiResponse = ApiResponse.success("Subscription created successfully", response);
            apiResponse.setCorrelationId(correlationId);
            
            return ResponseEntity.ok(apiResponse);
            
        } catch (Exception e) {
            logger.error("Subscription creation failed for user: {}", userId, e);
            throw e;
        }
    }
    
    /**
     * Updates an existing subscription.
     */
    @PutMapping("/{subscriptionId}")
    @Operation(summary = "Update subscription", description = "Updates an existing subscription")
    public ResponseEntity<ApiResponse<SubscriptionResponse>> updateSubscription(
            @PathVariable Long subscriptionId,
            @Valid @RequestBody SubscriptionRequest request,
            HttpServletRequest httpRequest) {
        
        String correlationId = CorrelationIdUtil.getCorrelationId();
        logger.info("Updating subscription: {}", subscriptionId);
        
        try {
            SubscriptionResponse response = subscriptionService.updateSubscription(subscriptionId, request, correlationId);
            ApiResponse<SubscriptionResponse> apiResponse = ApiResponse.success("Subscription updated successfully", response);
            apiResponse.setCorrelationId(correlationId);
            
            return ResponseEntity.ok(apiResponse);
            
        } catch (Exception e) {
            logger.error("Subscription update failed for subscription: {}", subscriptionId, e);
            throw e;
        }
    }
    
    /**
     * Cancels a subscription.
     */
    @DeleteMapping("/{subscriptionId}")
    @Operation(summary = "Cancel subscription", description = "Cancels an existing subscription")
    public ResponseEntity<ApiResponse<SubscriptionResponse>> cancelSubscription(
            @PathVariable Long subscriptionId,
            HttpServletRequest httpRequest) {
        
        String correlationId = CorrelationIdUtil.getCorrelationId();
        logger.info("Cancelling subscription: {}", subscriptionId);
        
        try {
            SubscriptionResponse response = subscriptionService.cancelSubscription(subscriptionId, correlationId);
            ApiResponse<SubscriptionResponse> apiResponse = ApiResponse.success("Subscription cancelled successfully", response);
            apiResponse.setCorrelationId(correlationId);
            
            return ResponseEntity.ok(apiResponse);
            
        } catch (Exception e) {
            logger.error("Subscription cancellation failed for subscription: {}", subscriptionId, e);
            throw e;
        }
    }
    
    /**
     * Gets a subscription by ID.
     */
    @GetMapping("/{subscriptionId}")
    @Operation(summary = "Get subscription", description = "Retrieves a subscription by ID")
    public ResponseEntity<ApiResponse<SubscriptionResponse>> getSubscription(@PathVariable Long subscriptionId) {
        String correlationId = CorrelationIdUtil.getCorrelationId();
        logger.info("Retrieving subscription: {}", subscriptionId);
        
        try {
            SubscriptionResponse response = subscriptionService.getSubscription(subscriptionId);
            ApiResponse<SubscriptionResponse> apiResponse = ApiResponse.success("Subscription retrieved successfully", response);
            apiResponse.setCorrelationId(correlationId);
            
            return ResponseEntity.ok(apiResponse);
            
        } catch (Exception e) {
            logger.error("Failed to retrieve subscription: {}", subscriptionId, e);
            throw e;
        }
    }
    
    /**
     * Gets all subscriptions for the current user.
     */
    @GetMapping
    @Operation(summary = "Get user subscriptions", description = "Retrieves all subscriptions for the current user")
    public ResponseEntity<ApiResponse<List<SubscriptionResponse>>> getUserSubscriptions(HttpServletRequest httpRequest) {
        String correlationId = CorrelationIdUtil.getCorrelationId();
        Long userId = (Long) httpRequest.getAttribute("userId");
        
        logger.info("Retrieving subscriptions for user: {}", userId);
        
        try {
            List<SubscriptionResponse> responses = subscriptionService.getUserSubscriptions(userId);
            ApiResponse<List<SubscriptionResponse>> apiResponse = ApiResponse.success("Subscriptions retrieved successfully", responses);
            apiResponse.setCorrelationId(correlationId);
            
            return ResponseEntity.ok(apiResponse);
            
        } catch (Exception e) {
            logger.error("Failed to retrieve subscriptions for user: {}", userId, e);
            throw e;
        }
    }
}
