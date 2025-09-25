package com.payments.service;

import com.payments.model.entity.IdempotencyKey;
import com.payments.repository.IdempotencyKeyRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.concurrent.TimeUnit;

/**
 * Service for idempotency key management.
 */
@Service
@Transactional
public class IdempotencyService {
    
    private static final Logger logger = LoggerFactory.getLogger(IdempotencyService.class);
    
    private final IdempotencyKeyRepository idempotencyKeyRepository;
    private final RedisTemplate<String, Object> redisTemplate;
    
    public IdempotencyService(IdempotencyKeyRepository idempotencyKeyRepository, RedisTemplate<String, Object> redisTemplate) {
        this.idempotencyKeyRepository = idempotencyKeyRepository;
        this.redisTemplate = redisTemplate;
    }
    
    public String checkIdempotency(String keyValue, String endpoint, String correlationId) {
        logger.debug("Checking idempotency for key: {} and endpoint: {}", keyValue, endpoint);
        
        // Check Redis cache first
        String cacheKey = "idempotency:" + keyValue + ":" + endpoint;
        String cachedResponse = (String) redisTemplate.opsForValue().get(cacheKey);
        
        if (cachedResponse != null) {
            logger.debug("Found cached response for idempotency key: {}", keyValue);
            return cachedResponse;
        }
        
        // Check database
        IdempotencyKey idempotencyKey = idempotencyKeyRepository.findByKeyValueAndEndpoint(keyValue, endpoint).orElse(null);
        
        if (idempotencyKey != null && !isExpired(idempotencyKey)) {
            // Cache the response in Redis
            redisTemplate.opsForValue().set(cacheKey, idempotencyKey.getResponseBody(), 24, TimeUnit.HOURS);
            
            logger.debug("Found database response for idempotency key: {}", keyValue);
            return idempotencyKey.getResponseBody();
        }
        
        return null;
    }
    
    public void storeIdempotencyKey(String keyValue, String endpoint, String requestBody, String responseBody, String correlationId) {
        logger.debug("Storing idempotency key: {} for endpoint: {}", keyValue, endpoint);
        
        // Store in database
        IdempotencyKey idempotencyKey = new IdempotencyKey();
        idempotencyKey.setKeyValue(keyValue);
        idempotencyKey.setEndpoint(endpoint);
        idempotencyKey.setRequestBody(requestBody);
        idempotencyKey.setResponseBody(responseBody);
        idempotencyKey.setCorrelationId(correlationId);
        idempotencyKey.setCreatedAt(LocalDateTime.now());
        
        idempotencyKeyRepository.save(idempotencyKey);
        
        // Cache in Redis
        String cacheKey = "idempotency:" + keyValue + ":" + endpoint;
        redisTemplate.opsForValue().set(cacheKey, responseBody, 24, TimeUnit.HOURS);
        
        logger.debug("Idempotency key stored successfully: {}", keyValue);
    }
    
    private boolean isExpired(IdempotencyKey idempotencyKey) {
        return idempotencyKey.getCreatedAt().isBefore(LocalDateTime.now().minusHours(24));
    }
}

```

```

