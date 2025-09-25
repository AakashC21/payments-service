package com.payments.repository;

import com.payments.model.entity.WebhookEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Repository interface for WebhookEvent entity operations.
 */
@Repository
public interface WebhookEventRepository extends JpaRepository<WebhookEvent, Long> {
    
    List<WebhookEvent> findByStatus(WebhookEvent.ProcessingStatus status);
    
    List<WebhookEvent> findByEventType(String eventType);
    
    @Query("SELECT we FROM WebhookEvent we WHERE we.createdAt >= :fromDate AND we.createdAt <= :toDate")
    List<WebhookEvent> findByDateRange(@Param("fromDate") LocalDateTime fromDate, @Param("toDate") LocalDateTime toDate);
    
    @Query("SELECT we FROM WebhookEvent we WHERE we.status = 'RETRYING' AND we.retryCount < 3")
    List<WebhookEvent> findRetryableEvents();
}

```

```

