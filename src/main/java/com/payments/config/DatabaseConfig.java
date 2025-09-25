package com.payments.config;

import liquibase.integration.spring.SpringLiquibase;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.transaction.PlatformTransactionManager;

import javax.sql.DataSource;
import java.util.Properties;

/**
 * Database configuration for PostgreSQL with JPA/Hibernate.
 * 
 * Key features:
 * - JPA auditing for automatic timestamp management
 * - Liquibase for database migrations
 * - Hibernate configuration optimized for production
 * - Transaction management setup
 */
@Configuration
@EnableJpaRepositories(basePackages = "com.payments.repository")
@EnableJpaAuditing
public class DatabaseConfig {

    @Value("${spring.jpa.hibernate.ddl-auto:none}")
    private String hibernateDdlAuto;

    @Value("${spring.jpa.show-sql:false}")
    private boolean showSql;

    /**
     * Configures Liquibase for database migrations.
     * This ensures schema changes are versioned and applied consistently.
     */
    @Bean
    public SpringLiquibase liquibase(DataSource dataSource) {
        SpringLiquibase liquibase = new SpringLiquibase();
        liquibase.setDataSource(dataSource);
        liquibase.setChangeLog("classpath:db/migration/changelog.xml");
        liquibase.setDefaultSchema("public");
        return liquibase;
    }

    /**
     * Configures Hibernate properties for production use.
     * Key settings:
     * - Connection pooling
     * - SQL dialect for PostgreSQL
     * - Batch processing for performance
     * - Second-level cache configuration
     */
    @Bean
    public Properties hibernateProperties() {
        Properties properties = new Properties();
        properties.setProperty("hibernate.dialect", "org.hibernate.dialect.PostgreSQLDialect");
        properties.setProperty("hibernate.hbm2ddl.auto", hibernateDdlAuto);
        properties.setProperty("hibernate.show_sql", String.valueOf(showSql));
        properties.setProperty("hibernate.format_sql", "true");
        properties.setProperty("hibernate.jdbc.batch_size", "25");
        properties.setProperty("hibernate.order_inserts", "true");
        properties.setProperty("hibernate.order_updates", "true");
        properties.setProperty("hibernate.jdbc.batch_versioned_data", "true");
        properties.setProperty("hibernate.connection.provider_disables_autocommit", "true");
        return properties;
    }

    /**
     * Configures the entity manager factory with Hibernate.
     * This is the core of JPA configuration.
     */
    @Bean
    public LocalContainerEntityManagerFactoryBean entityManagerFactory(DataSource dataSource) {
        LocalContainerEntityManagerFactoryBean em = new LocalContainerEntityManagerFactoryBean();
        em.setDataSource(dataSource);
        em.setPackagesToScan("com.payments.model.entity");
        
        HibernateJpaVendorAdapter vendorAdapter = new HibernateJpaVendorAdapter();
        em.setJpaVendorAdapter(vendorAdapter);
        em.setJpaProperties(hibernateProperties());
        
        return em;
    }

    /**
     * Configures transaction management.
     * Ensures ACID properties for database operations.
     */
    @Bean
    public PlatformTransactionManager transactionManager(LocalContainerEntityManagerFactoryBean entityManagerFactory) {
        JpaTransactionManager transactionManager = new JpaTransactionManager();
        transactionManager.setEntityManagerFactory(entityManagerFactory.getObject());
        return transactionManager;
    }
}
```

```java:src/main/java/com/payments/config/RedisConfig.java
package com.payments.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

/**
 * Redis configuration for caching and message queuing.
 * 
 * Uses:
 * - Idempotency key caching for fast lookups
 * - Webhook event queuing for async processing
 * - Session storage for JWT tokens
 * 
 * Key design decisions:
 * - Lettuce connection factory for better performance
 * - JSON serialization for complex objects
 * - String serialization for simple keys
 */
@Configuration
public class RedisConfig {

    @Value("${spring.data.redis.host:localhost}")
    private String redisHost;

    @Value("${spring.data.redis.port:6379}")
    private int redisPort;

    @Value("${spring.data.redis.password:}")
    private String redisPassword;

    @Value("${spring.data.redis.database:0}")
    private int redisDatabase;

    /**
     * Configures Redis connection factory using Lettuce.
     * Lettuce is preferred over Jedis for better async support.
     */
    @Bean
    public RedisConnectionFactory redisConnectionFactory() {
        LettuceConnectionFactory factory = new LettuceConnectionFactory();
        factory.setHostName(redisHost);
        factory.setPort(redisPort);
        factory.setDatabase(redisDatabase);
        if (!redisPassword.isEmpty()) {
            factory.setPassword(redisPassword);
        }
        return factory;
    }

    /**
     * Configures Redis template with proper serialization.
     * 
     * Serialization strategy:
     * - String keys for simple identifiers
     * - JSON values for complex objects
     * - This allows easy debugging and cross-language compatibility
     */
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        
        // Use String serializer for keys
        template.setKeySerializer(new StringRedisSerializer());
        template.setHashKeySerializer(new StringRedisSerializer());
        
        // Use JSON serializer for values
        template.setValueSerializer(new GenericJackson2JsonRedisSerializer());
        template.setHashValueSerializer(new GenericJackson2JsonRedisSerializer());
        
        template.afterPropertiesSet();
        return template;
    }

    /**
     * Configures Redis message listener container for webhook processing.
     * This enables pub/sub functionality for async event handling.
     */
    @Bean
    public RedisMessageListenerContainer redisMessageListenerContainer(
            RedisConnectionFactory connectionFactory) {
        RedisMessageListenerContainer container = new RedisMessageListenerContainer();
        container.setConnectionFactory(connectionFactory);
        return container;
    }
}
```

```java:src/main/java/com/payments/config/SecurityConfig.java
package com.payments.config;

import com.payments.middleware.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

/**
 * Security configuration for JWT-based authentication.
 * 
 * Security principles:
 * - Stateless authentication using JWT
 * - CORS enabled for frontend integration
 * - Public endpoints for auth and webhooks
 * - Protected endpoints for all payment operations
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${app.security.jwt.secret}")
    private String jwtSecret;

    /**
     * Configures the security filter chain.
     * 
     * Key security features:
     * - CSRF disabled (not needed for stateless API)
     * - Session management set to stateless
     * - CORS configuration for cross-origin requests
     * - JWT filter applied to all requests except public ones
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .authorizeHttpRequests(authz -> authz
                // Public endpoints
                .requestMatchers("/api/v1/auth/login").permitAll()
                .requestMatchers("/api/v1/webhooks/**").permitAll()
                .requestMatchers("/actuator/health").permitAll()
                .requestMatchers("/actuator/metrics").permitAll()
                .requestMatchers("/swagger-ui/**").permitAll()
                .requestMatchers("/v3/api-docs/**").permitAll()
                // All other endpoints require authentication
                .anyRequest().authenticated()
            )
            .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }

    /**
     * Configures CORS for frontend integration.
     * Allows cross-origin requests from configured origins.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    /**
     * Creates JWT authentication filter.
     * This filter extracts and validates JWT tokens from requests.
     */
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(jwtSecret);
    }

    /**
     * Password encoder for user credentials.
     * Uses BCrypt for secure password hashing.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

```java:src/main/java/com/payments/config/OpenTelemetryConfig.java
package com.payments.config;

import io.micrometer.core.instrument.MeterRegistry;
import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.exporter.prometheus.PrometheusHttpServer;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.metrics.SdkMeterProvider;
import io.opentelemetry.sdk.resources.Resource;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.semconv.ResourceAttributes;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * OpenTelemetry configuration for distributed tracing and metrics.
 * 
 * Key features:
 * - Distributed tracing across service boundaries
 * - Prometheus metrics endpoint
 * - Correlation ID propagation
 * - Performance monitoring
 */
@Configuration
public class OpenTelemetryConfig {

    /**
     * Configures OpenTelemetry SDK with tracing and metrics.
     * 
     * Components:
     * - Tracer for distributed tracing
     * - Meter for metrics collection
     * - Prometheus exporter for metrics endpoint
     */
    @Bean
    public OpenTelemetry openTelemetry(MeterRegistry meterRegistry) {
        // Configure resource attributes for service identification
        Resource resource = Resource.getDefault()
            .merge(Resource.create(Attributes.of(
                ResourceAttributes.SERVICE_NAME, "payments-service",
                ResourceAttributes.SERVICE_VERSION, "1.0.0"
            )));

        // Configure Prometheus metrics exporter
        PrometheusHttpServer prometheusExporter = PrometheusHttpServer.builder()
            .setPort(9464)
            .build();

        // Configure meter provider with Prometheus exporter
        SdkMeterProvider meterProvider = SdkMeterProvider.builder()
            .setResource(resource)
            .registerMetricReader(prometheusExporter)
            .build();

        // Configure tracer provider
        SdkTracerProvider tracerProvider = SdkTracerProvider.builder()
            .setResource(resource)
            .build();

        // Build OpenTelemetry SDK
        OpenTelemetrySdk openTelemetry = OpenTelemetrySdk.builder()
            .setMeterProvider(meterProvider)
            .setTracerProvider(tracerProvider)
            .build();

        return openTelemetry;
    }

    /**
     * Creates tracer instance for distributed tracing.
     * Used throughout the application for span creation.
     */
    @Bean
    public Tracer tracer(OpenTelemetry openTelemetry) {
        return openTelemetry.getTracer("payments-service");
    }
}
```

```java:src/main/java/com/payments/config/SwaggerConfig.java
package com.payments.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.Components;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Swagger/OpenAPI configuration for API documentation.
 * 
 * Features:
 * - Interactive API documentation
 * - JWT authentication documentation
 * - Request/response examples
 * - Automatic endpoint discovery
 */
@Configuration
public class SwaggerConfig {

    /**
     * Configures OpenAPI specification with JWT authentication.
     * 
     * Key features:
     * - API versioning and metadata
     * - JWT Bearer token authentication
     * - Security requirements for protected endpoints
     */
    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
            .info(new Info()
                .title("Payments Service API")
                .version("1.0.0")
                .description("REST API for payment processing with Authorize.Net integration")
                .license(new License().name("MIT").url("https://opensource.org/licenses/MIT")))
            .components(new Components()
                .addSecuritySchemes("bearerAuth", new SecurityScheme()
                    .type(SecurityScheme.Type.HTTP)
                    .scheme("bearer")
                    .bearerFormat("JWT")
                    .description("JWT token for authentication")))
            .addSecurityItem(new SecurityRequirement().addList("bearerAuth"));
    }
}
```

Now let me create the entity models:

```java:src/main/java/com/payments/model/entity/User.java
package com.payments.model.entity;

import jakarta.persistence.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * User entity representing system users who can make payments.
 * 
 * Key features:
 * - JPA auditing for automatic timestamp management
 * - One-to-many relationship with orders
 * - Encrypted password storage
 * - Email uniqueness constraint
 */
@Entity
@Table(name = "users", indexes = {
    @Index(name = "idx_user_email", columnList = "email", unique = true),
    @Index(name = "idx_user_created_at", columnList = "createdAt")
})
@EntityListeners(AuditingEntityListener.class)
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, unique = true, length = 255)
    private String email;
    
    @Column(nullable = false, length = 255)
    private String passwordHash;
    
    @Column(length = 100)
    private String firstName;
    
    @Column(length = 100)
    private String lastName;
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserStatus status = UserStatus.ACTIVE;
    
    @CreatedDate
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;
    
    @LastModifiedDate
    private LocalDateTime updatedAt;
    
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Order> orders = new ArrayList<>();
    
    // Constructors
    public User() {}
    
    public User(String email, String passwordHash, String firstName, String lastName) {
        this.email = email;
        this.passwordHash = passwordHash;
        this.firstName = firstName;
        this.lastName = lastName;
    }
    
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    
    public String getPasswordHash() { return passwordHash; }
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }
    
    public String getFirstName() { return firstName; }
    public void setFirstName(String firstName) { this.firstName = firstName; }
    
    public String getLastName() { return lastName; }
    public void setLastName(String lastName) { this.lastName = lastName; }
    
    public UserStatus getStatus() { return status; }
    public void setStatus(UserStatus status) { this.status = status; }
    
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    
    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }
    
    public List<Order> getOrders() { return orders; }
    public void setOrders(List<Order> orders) { this.orders = orders; }
    
    // Enum for user status
    public enum UserStatus {
        ACTIVE, INACTIVE, SUSPENDED
    }
}
```

```java:src/main/java/com/payments/model/entity/Order.java
package com.payments.model.entity;

import jakarta.persistence.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Order entity representing a customer order that can have multiple payments.
 * 
 * Key features:
 * - One-to-many relationship with payments
 * - Many-to-one relationship with user
 * - Order status tracking
 * - Currency support
 */
@Entity
@Table(name = "orders", indexes = {
    @Index(name = "idx_order_user_id", columnList = "userId"),
    @Index(name = "idx_order_status", columnList = "status"),
    @Index(name = "idx_order_created_at", columnList = "createdAt"),
    @Index(name = "idx_order_order_number", columnList = "orderNumber", unique = true)
})
@EntityListeners(AuditingEntityListener.class)
public class Order {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, unique = true, length = 50)
    private String orderNumber;
    
    @Column(nullable = false)
    private Long userId;
    
    @Column(nullable = false, precision = 10, scale = 2)
    private BigDecimal totalAmount;
    
    @Column(length = 3)
    private String currency = "USD";
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private OrderStatus status = OrderStatus.PENDING;
    
    @Column(length = 500)
    private String description;
    
    @Column(length = 1000)
    private String metadata;
    
    @CreatedDate
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;
    
    @LastModifiedDate
    private LocalDateTime updatedAt;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "userId", insertable = false, updatable = false)
    private User user;
    
    @OneToMany(mappedBy = "order", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Payment> payments = new ArrayList<>();
    
    // Constructors
    public Order() {}
    
    public Order(String orderNumber, Long userId, BigDecimal totalAmount, String description) {
        this.orderNumber = orderNumber;
        this.userId = userId;
        this.totalAmount = totalAmount;
        this.description = description;
    }
    
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getOrderNumber() { return orderNumber; }
    public void setOrderNumber(String orderNumber) { this.orderNumber = orderNumber; }
    
    public Long getUserId() { return userId; }
    public void setUserId(Long userId) { this.userId = userId; }
    
    public BigDecimal getTotalAmount() { return totalAmount; }
    public void setTotalAmount(BigDecimal totalAmount) { this.totalAmount = totalAmount; }
    
    public String getCurrency() { return currency; }
    public void setCurrency(String currency) { this.currency = currency; }
    
    public OrderStatus getStatus() { return status; }
    public void setStatus(OrderStatus status) { this.status = status; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public String getMetadata() { return metadata; }
    public void setMetadata(String metadata) { this.metadata = metadata; }
    
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    
    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }
    
    public User getUser() { return user; }
    public void setUser(User user) { this.user = user; }
    
    public List<Payment> getPayments() { return payments; }
    public void setPayments(List<Payment> payments) { this.payments = payments; }
    
    // Enum for order status
    public enum OrderStatus {
        PENDING, PAID, PARTIALLY_PAID, REFUNDED, CANCELLED, FAILED
    }
}
```

```java:src/main/java/com/payments/model/entity/Payment.java
package com.payments.model.entity;

import jakarta.persistence.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * Payment entity representing individual payment transactions.
 * 
 * Key features:
 * - Links to orders and subscriptions
 * - Payment status tracking
 * - Authorize.Net transaction ID storage
 * - Support for partial payments and refunds
 */
@Entity
@Table(name = "payments", indexes = {
    @Index(name = "idx_payment_order_id", columnList = "orderId"),
    @Index(name = "idx_payment_subscription_id", columnList = "subscriptionId"),
    @Index(name = "idx_payment_status", columnList = "status"),
    @Index(name = "idx_payment_auth_net_id", columnList = "authorizeNetTransactionId"),
    @Index(name = "idx_payment_created_at", columnList = "createdAt")
})
@EntityListeners(AuditingEntityListener.class)
public class Payment {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false)
    private Long orderId;
    
    @Column
    private Long subscriptionId;
    
    @Column(nullable = false, precision = 10, scale = 2)
    private BigDecimal amount;
    
    @Column(length = 3)
    private String currency = "USD";
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private PaymentType type;
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private PaymentStatus status;
    
    @Column(length = 255)
    private String authorizeNetTransactionId;
    
    @Column(length = 1000)
    private String authorizeNetResponse;
    
    @Column(length = 500)
    private String failureReason;
    
    @Column(length = 100)
    private String correlationId;
    
    @Column(length = 100)
    private String idempotencyKey;
    
    @CreatedDate
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;
    
    @LastModifiedDate
    private LocalDateTime updatedAt;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "orderId", insertable = false, updatable = false)
    private Order order;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "subscriptionId", insertable = false, updatable = false)
    private Subscription subscription;
    
    // Constructors
    public Payment() {}
    
    public Payment(Long orderId, BigDecimal amount, PaymentType type, PaymentStatus status) {
        this.orderId = orderId;
        this.amount = amount;
        this.type = type;
        this.status = status;
    }
    
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public Long getOrderId() { return orderId; }
    public void setOrderId(Long orderId) { this.orderId = orderId; }
    
    public Long getSubscriptionId() { return subscriptionId; }
    public void setSubscriptionId(Long subscriptionId) { this.subscriptionId = subscriptionId; }
    
    public BigDecimal getAmount() { return amount; }
    public void setAmount(BigDecimal amount) { this.amount = amount; }
    
    public String getCurrency() { return currency; }
    public void setCurrency(String currency) { this.currency = currency; }
    
    public PaymentType getType() { return type; }
    public void setType(PaymentType type) { this.type = type; }
    
    public PaymentStatus getStatus() { return status; }
    public void setStatus(PaymentStatus status) { this.status = status; }
    
    public String getAuthorizeNetTransactionId() { return authorizeNetTransactionId; }
    public void setAuthorizeNetTransactionId(String authorizeNetTransactionId) { this.authorizeNetTransactionId = authorizeNetTransactionId; }
    
    public String getAuthorizeNetResponse() { return authorizeNetResponse; }
    public void setAuthorizeNetResponse(String authorizeNetResponse) { this.authorizeNetResponse = authorizeNetResponse; }
    
    public String getFailureReason() { return failureReason; }
    public void setFailureReason(String failureReason) { this.failureReason = failureReason; }
    
    public String getCorrelationId() { return correlationId; }
    public void setCorrelationId(String correlationId) { this.correlationId = correlationId; }
    
    public String getIdempotencyKey() { return idempotencyKey; }
    public void setIdempotencyKey(String idempotencyKey) { this.idempotencyKey = idempotencyKey; }
    
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    
    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }
    
    public Order getOrder() { return order; }
    public void setOrder(Order order) { this.order = order; }
    
    public Subscription getSubscription() { return subscription; }
    public void setSubscription(Subscription subscription) { this.subscription = subscription; }
    
    // Enums for payment types and statuses
    public enum PaymentType {
        PURCHASE, AUTHORIZE, CAPTURE, REFUND, VOID
    }
    
    public enum PaymentStatus {
        PENDING, AUTHORIZED, CAPTURED, REFUNDED, VOIDED, FAILED, DECLINED
    }
}
```

```java:src/main/java/com/payments/model/entity/Subscription.java
package com.payments.model.entity;

import jakarta.persistence.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * Subscription entity for recurring billing.
 * 
 * Key features:
 * - Recurring payment scheduling
 * - Subscription status management
 * - Authorize.Net subscription ID storage
 * - Trial period support
 */
@Entity
@Table(name = "subscriptions", indexes = {
    @Index(name = "idx_subscription_user_id", columnList = "userId"),
    @Index(name = "idx_subscription_status", columnList = "status"),
    @Index(name = "idx_subscription_auth_net_id", columnList = "authorizeNetSubscriptionId"),
    @Index(name = "idx_subscription_next_billing", columnList = "nextBillingDate")
})
@EntityListeners(AuditingEntityListener.class)
public class Subscription {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false)
    private Long userId;
    
    @Column(nullable = false, precision = 10, scale = 2)
    private BigDecimal amount;
    
    @Column(length = 3)
    private String currency = "USD";
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private SubscriptionStatus status = SubscriptionStatus.ACTIVE;
    
    @Column(length = 50)
    private String authorizeNetSubscriptionId;
    
    @Column(nullable = false)
    private LocalDateTime nextBillingDate;
    
    @Column
    private Integer billingIntervalDays = 30;
    
    @Column(length = 500)
    private String description;
    
    @Column(length = 1000)
    private String metadata;
    
    @Column
    private LocalDateTime trialEndDate;
    
    @CreatedDate
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;
    
    @LastModifiedDate
    private LocalDateTime updatedAt;
    
    // Constructors
    public Subscription() {}
    
    public Subscription(Long userId, BigDecimal amount, LocalDateTime nextBillingDate, String description) {
        this.userId = userId;
        this.amount = amount;
        this.nextBillingDate = nextBillingDate;
        this.description = description;
    }
    
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public Long getUserId() { return userId; }
    public void setUserId(Long userId) { this.userId = userId; }
    
    public BigDecimal getAmount() { return amount; }
    public void setAmount(BigDecimal amount) { this.amount = amount; }
    
    public String getCurrency() { return currency; }
    public void setCurrency(String currency) { this.currency = currency; }
    
    public SubscriptionStatus getStatus() { return status; }
    public void setStatus(SubscriptionStatus status) { this.status = status; }
    
    public String getAuthorizeNetSubscriptionId() { return authorizeNetSubscriptionId; }
    public void setAuthorizeNetSubscriptionId(String authorizeNetSubscriptionId) { this.authorizeNetSubscriptionId = authorizeNetSubscriptionId; }
    
    public LocalDateTime getNextBillingDate() { return nextBillingDate; }
    public void setNextBillingDate(LocalDateTime nextBillingDate) { this.nextBillingDate = nextBillingDate; }
    
    public Integer getBillingIntervalDays() { return billingIntervalDays; }
    public void setBillingIntervalDays(Integer billingIntervalDays) { this.billingIntervalDays = billingIntervalDays; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public String getMetadata() { return metadata; }
    public void setMetadata(String metadata) { this.metadata = metadata; }
    
    public LocalDateTime getTrialEndDate() { return trialEndDate; }
    public void setTrialEndDate(LocalDateTime trialEndDate) { this.trialEndDate = trialEndDate; }
    
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    
    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }
    
    // Enum for subscription status
    public enum SubscriptionStatus {
        ACTIVE, PAUSED, CANCELLED, EXPIRED, FAILED
    }
}
```

```java:src/main/java/com/payments/model/entity/IdempotencyKey.java
package com.payments.model.entity;

import jakarta.persistence.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

/**
 * Idempotency key entity for preventing duplicate operations.
 * 
 * Key features:
 * - Unique constraint on key value
 * - Request/response caching
 * - TTL-based expiration
 * - Correlation ID tracking
 */
@Entity
@Table(name = "idempotency_keys", indexes = {
    @Index(name = "idx_idempotency_key", columnList = "key", unique = true),
    @Index(name = "idx_idempotency_expires_at", columnList = "expiresAt")
})
@EntityListeners(AuditingEntityListener.class)
public class IdempotencyKey {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, unique = true, length = 255)
    private String key;
    
    @Column(nullable = false, columnDefinition = "TEXT")
    private String requestBody;
    
    @Column(columnDefinition = "TEXT")
    private String responseBody;
    
    @Column(length = 100)
    private String correlationId;
    
    @Column(length = 100)
    private String endpoint;
    
    @Column(nullable = false)
    private LocalDateTime expiresAt;
    
    @CreatedDate
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;
    
    // Constructors
    public IdempotencyKey() {}
    
    public IdempotencyKey(String key, String requestBody, String correlationId, String endpoint, LocalDateTime expiresAt) {
        this.key = key;
        this.requestBody = requestBody;
        this.correlationId = correlationId;
        this.endpoint = endpoint;
        this.expiresAt = expiresAt;
    }
    
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getKey() { return key; }
    public void setKey(String key) { this.key = key; }
    
    public String getRequestBody() { return requestBody; }
    public void setRequestBody(String requestBody) { this.requestBody = requestBody; }
    
    public String getResponseBody() { return responseBody; }
    public void setResponseBody(String responseBody) { this.responseBody = responseBody; }
    
    public String getCorrelationId() { return correlationId; }
    public void setCorrelationId(String correlationId) { this.correlationId = correlationId; }
    
    public String getEndpoint() { return endpoint; }
    public void setEndpoint(String endpoint) { this.endpoint = endpoint; }
    
    public LocalDateTime getExpiresAt() { return expiresAt; }
    public void setExpiresAt(LocalDateTime expiresAt) { this.expiresAt = expiresAt; }
    
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = create
