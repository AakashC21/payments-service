package com.payments.service;

import com.payments.gateway.AuthorizeNetGateway;
import com.payments.model.dto.PaymentRequest;
import com.payments.model.dto.PaymentResponse;
import com.payments.model.entity.Order;
import com.payments.model.entity.Payment;
import com.payments.repository.OrderRepository;
import com.payments.repository.PaymentRepository;
import com.payments.metrics.PaymentMetrics;
import io.micrometer.core.instrument.Timer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * Service for payment processing operations.
 */
@Service
@Transactional
public class PaymentService {
    
    private static final Logger logger = LoggerFactory.getLogger(PaymentService.class);
    
    private final PaymentRepository paymentRepository;
    private final OrderRepository orderRepository;
    private final AuthorizeNetGateway authorizeNetGateway;
    private final PaymentMetrics paymentMetrics;
    
    public PaymentService(PaymentRepository paymentRepository,
                         OrderRepository orderRepository,
                         AuthorizeNetGateway authorizeNetGateway,
                         PaymentMetrics paymentMetrics) {
        this.paymentRepository = paymentRepository;
        this.orderRepository = orderRepository;
        this.authorizeNetGateway = authorizeNetGateway;
        this.paymentMetrics = paymentMetrics;
    }
    
    public PaymentResponse processPurchase(PaymentRequest request, String correlationId) {
        logger.info("Processing purchase for order: {}", request.getOrderNumber());
        
        Timer.Sample sample = Timer.start();
        try {
            // Create or get order
            Order order = createOrGetOrder(request);
            
            // Create payment entity
            Payment payment = new Payment();
            payment.setOrderId(order.getId());
            payment.setUserId(order.getUserId());
            payment.setAmount(request.getAmount());
            payment.setCurrency(request.getCurrency());
            payment.setStatus(Payment.PaymentStatus.PENDING);
            payment.setPaymentMethod(request.getPaymentMethod());
            payment.setCreatedAt(LocalDateTime.now());
            
            payment = paymentRepository.save(payment);
            
            // Process with Authorize.Net (mock implementation)
            String transactionId = authorizeNetGateway.processPurchase(request);
            payment.setAuthorizeNetTransactionId(transactionId);
            payment.setStatus(Payment.PaymentStatus.COMPLETED);
            payment.setProcessedAt(LocalDateTime.now());
            
            payment = paymentRepository.save(payment);
            
            paymentMetrics.incrementPaymentsProcessed();
            
            return convertToResponse(payment);
            
        } catch (Exception e) {
            logger.error("Purchase processing failed for order: {}", request.getOrderNumber(), e);
            throw e;
        } finally {
            sample.stop(paymentMetrics.getPaymentProcessingTime());
        }
    }
    
    public PaymentResponse authorizePayment(PaymentRequest request, String correlationId) {
        logger.info("Authorizing payment for order: {}", request.getOrderNumber());
        
        Order order = createOrGetOrder(request);
        
        Payment payment = new Payment();
        payment.setOrderId(order.getId());
        payment.setUserId(order.getUserId());
        payment.setAmount(request.getAmount());
        payment.setCurrency(request.getCurrency());
        payment.setStatus(Payment.PaymentStatus.AUTHORIZED);
        payment.setPaymentMethod(request.getPaymentMethod());
        payment.setCreatedAt(LocalDateTime.now());
        
        payment = paymentRepository.save(payment);
        
        String transactionId = authorizeNetGateway.authorizePayment(request);
        payment.setAuthorizeNetTransactionId(transactionId);
        payment = paymentRepository.save(payment);
        
        return convertToResponse(payment);
    }
    
    public PaymentResponse capturePayment(String authorizationTransactionId, BigDecimal amount, String correlationId) {
        logger.info("Capturing payment for transaction: {}", authorizationTransactionId);
        
        Payment payment = paymentRepository.findByAuthorizeNetTransactionId(authorizationTransactionId)
            .orElseThrow(() -> new RuntimeException("Payment not found"));
        
        payment.setStatus(Payment.PaymentStatus.COMPLETED);
        payment.setProcessedAt(LocalDateTime.now());
        
        payment = paymentRepository.save(payment);
        
        return convertToResponse(payment);
    }
    
    public PaymentResponse refundPayment(String originalTransactionId, BigDecimal amount, String correlationId) {
        logger.info("Processing refund for transaction: {}", originalTransactionId);
        
        Payment payment = paymentRepository.findByAuthorizeNetTransactionId(originalTransactionId)
            .orElseThrow(() -> new RuntimeException("Payment not found"));
        
        payment.setStatus(Payment.PaymentStatus.REFUNDED);
        payment.setProcessedAt(LocalDateTime.now());
        
        payment = paymentRepository.save(payment);
        
        return convertToResponse(payment);
    }
    
    public PaymentResponse voidPayment(String transactionId, String correlationId) {
        logger.info("Voiding payment for transaction: {}", transactionId);
        
        Payment payment = paymentRepository.findByAuthorizeNetTransactionId(transactionId)
            .orElseThrow(() -> new RuntimeException("Payment not found"));
        
        payment.setStatus(Payment.PaymentStatus.VOIDED);
        payment.setProcessedAt(LocalDateTime.now());
        
        payment = paymentRepository.save(payment);
        
        return convertToResponse(payment);
    }
    
    private Order createOrGetOrder(PaymentRequest request) {
        return orderRepository.findByOrderNumber(request.getOrderNumber())
            .orElseGet(() -> {
                Order order = new Order();
                order.setOrderNumber(request.getOrderNumber());
                order.setUserId(1L); // TODO: Get from security context
                order.setAmount(request.getAmount());
                order.setCurrency(request.getCurrency());
                order.setStatus(Order.OrderStatus.PENDING);
                order.setCreatedAt(LocalDateTime.now());
                return orderRepository.save(order);
            });
    }
    
    private PaymentResponse convertToResponse(Payment payment) {
        PaymentResponse response = new PaymentResponse();
        response.setId(payment.getId());
        response.setTransactionId(payment.getAuthorizeNetTransactionId());
        response.setAmount(payment.getAmount());
        response.setCurrency(payment.getCurrency());
        response.setStatus(payment.getStatus().name());
        response.setPaymentMethod(payment.getPaymentMethod());
        response.setCreatedAt(payment.getCreatedAt());
        response.setProcessedAt(payment.getProcessedAt());
        return response;
    }
}



