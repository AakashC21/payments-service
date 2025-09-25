package com.payments;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Main Spring Boot application class for the Payments Service.
 * 
 * Key annotations:
 * - @SpringBootApplication: Enables auto-configuration, component scanning, and configuration properties
 * - @EnableAsync: Enables asynchronous processing for webhook event handling
 * - @EnableScheduling: Enables scheduled tasks (if needed for cleanup jobs)
 */
@SpringBootApplication
@EnableAsync
@EnableScheduling
public class PaymentsServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(PaymentsServiceApplication.class, args);
    }
}
