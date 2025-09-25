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

```

