package com.payments.worker;

import com.payments.service.WebhookService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Worker for processing webhook events asynchronously.
 * 
 * Key features:
 * - Scheduled processing of webhook events
 * - Retry mechanism for failed events
 * - Error handling and logging
 */
@Component
public class WebhookEventWorker {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookEventWorker.class);
    
    private final WebhookService webhookService;
    
    public WebhookEventWorker(WebhookService webhookService) {
        this.webhookService = webhookService;
    }
    
    /**
     * Processes webhook events every 30 seconds.
     */
    @Scheduled(fixedDelay = 30000) // 30 seconds
    public void processWebhookEvents() {
        try {
            logger.debug("Starting webhook event processing");
            webhookService.processQueuedWebhookEvents();
        } catch (Exception e) {
            logger.error("Error processing webhook events: {}", e.getMessage(), e);
        }
    }
}

