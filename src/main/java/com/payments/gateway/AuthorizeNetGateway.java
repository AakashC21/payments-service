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

```

