package com.payments.controller;

import com.payments.service.WebhookService;
import com.payments.util.CorrelationIdUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Controller for webhook operations.
 * 
 * Key features:
 * - Webhook endpoint for Authorize.Net
 * - Signature verification
 * - Event processing
 */
@RestController
@RequestMapping("/api/v1/webhooks")
@Tag(name = "Webhooks", description = "Webhook processing operations")
public class WebhookController {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookController.class);
    
    private final WebhookService webhookService;
    
    public WebhookController(WebhookService webhookService) {
        this.webhookService = webhookService;
    }
    
    /**
     * Receives webhook events from Authorize.Net.
     */
    @PostMapping("/authorizenet")
    @Operation(summary = "Authorize.Net webhook", description = "Receives webhook events from Authorize.Net")
    public ResponseEntity<String> receiveWebhook(
            @RequestBody String payload,
            @RequestHeader("X-ANET-Signature") String signature) {
        
        String correlationId = CorrelationIdUtil.getCorrelationId();
        logger.info("Received webhook event with correlation ID: {}", correlationId);
        
        try {
            webhookService.processWebhookEvent(payload, signature, correlationId);
            return ResponseEntity.ok("Webhook received successfully");
            
        } catch (Exception e) {
            logger.error("Failed to process webhook event: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body("Webhook processing failed: " + e.getMessage());
        }
    }
}

