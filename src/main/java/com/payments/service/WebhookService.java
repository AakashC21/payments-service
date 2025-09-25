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



