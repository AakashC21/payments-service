package com.payments.config;

import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Metrics configuration using Spring Boot's built-in Micrometer.
 * 
 * Key features:
 * - Prometheus metrics endpoint
 * - Performance monitoring
 * - Custom metrics support
 */
@Configuration
public class OpenTelemetryConfig {

    /**
     * Configures metrics registry for monitoring.
     * Spring Boot automatically configures Micrometer with Prometheus support.
     */
    @Bean
    public MeterRegistry meterRegistry(MeterRegistry registry) {
        return registry;
    }
}
