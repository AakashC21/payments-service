# Payments Service

A comprehensive Spring Boot backend service for payment processing with Authorize.Net integration.

## Features

- **Payment Processing**: Purchase, authorize, capture, refund, and void operations
- **Subscription Management**: Create, update, cancel recurring subscriptions
- **Webhook Processing**: Secure webhook handling with signature verification
- **Idempotency**: Request deduplication using Redis and PostgreSQL
- **JWT Authentication**: Secure API endpoints with JWT tokens
- **Distributed Tracing**: Correlation IDs for request tracking
- **Metrics & Monitoring**: Prometheus metrics and health checks
- **API Documentation**: Swagger/OpenAPI documentation

## Tech Stack

- **Language**: Java 17+
- **Framework**: Spring Boot 3.x
- **Database**: PostgreSQL
- **Cache/Queue**: Redis
- **Build Tool**: Maven
- **Containerization**: Docker + Docker Compose
- **CI/CD**: GitHub Actions
- **Documentation**: Swagger/OpenAPI
- **Testing**: JUnit + Mockito + Testcontainers
- **Monitoring**: OpenTelemetry + Prometheus

## Quick Start

### Prerequisites

- Java 17+
- Maven 3.6+
- Docker & Docker Compose
- PostgreSQL 15+
- Redis 7+

### Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd payments-service
   ```

2. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Start infrastructure services**
   ```bash
   docker-compose -f docker/docker-compose.yml up -d postgres redis
   ```

4. **Run the application**
   ```bash
   ./mvnw spring-boot:run
   ```

5. **Access the application**
   - API: http://localhost:8080
   - Swagger UI: http://localhost:8080/swagger-ui.html
   - Health Check: http://localhost:8080/actuator/health
   - Metrics: http://localhost:8080/actuator/metrics

### Using Docker Compose

```bash
# Start all services
docker-compose -f docker/docker-compose.yml up -d

# View logs
docker-compose -f docker/docker-compose.yml logs -f payments-service

# Stop services
docker-compose -f docker/docker-compose.yml down
```

## API Usage

### Authentication

1. **Register a user** (for testing)
   ```bash
   curl -X POST http://localhost:8080/api/v1/auth/register \
     -H "Content-Type: application/json" \
     -d '{"email": "test@example.com", "password": "password123"}'
   ```

2. **Login**
   ```bash
   curl -X POST http://localhost:8080/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email": "test@example.com", "password": "password123"}'
   ```

3. **Use the JWT token** in subsequent requests
   ```bash
   curl -X GET http://localhost:8080/api/v1/subscriptions \
     -H "Authorization: Bearer <your-jwt-token>"
   ```

### Payment Processing

**Process a purchase**
```bash
curl -X POST http://localhost:8080/api/v1/payments/purchase \
  -H "Authorization: Bearer <your-jwt-token>" \
  -H "Content-Type: application/json" \
  -H "X-Correlation-ID: $(uuidgen)" \
  -H "Idempotency-Key: $(uuidgen)" \
  -d '{
    "orderNumber": "ORD-001",
    "amount": 100.00,
    "currency": "USD",
    "type": "PURCHASE",
    "cardNumber": "4111111111111111",
    "expirationDate": "12/25",
    "cvv": "123",
    "cardholderName": "John Doe"
  }'
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_HOST` | PostgreSQL host | localhost |
| `DB_USERNAME` | Database username | payments_user |
| `DB_PASSWORD` | Database password | payments_pass |
| `REDIS_HOST` | Redis host | localhost |
| `JWT_SECRET` | JWT signing secret | (required) |
| `AUTHORIZE_NET_LOGIN_ID` | Authorize.Net login ID | (required) |
| `AUTHORIZE_NET_TRANSACTION_KEY` | Authorize.Net transaction key | (required) |

### Profiles

- `dev`: Development configuration
- `test`: Test configuration
- `prod`: Production configuration

## Testing

```bash
# Run all tests
./mvnw test

# Run with coverage
./mvnw test jacoco:report

# Run integration tests
./mvnw test -Dtest=*IntegrationTest
```

## Monitoring

### Health Checks
- **Health**: `/actuator/health`
- **Metrics**: `/actuator/metrics`
- **Prometheus**: `/actuator/prometheus`

### Key Metrics
- `payments_total`: Total payment attempts
- `payments_successful_total`: Successful payments
- `payments_failed_total`: Failed payments
- `webhooks_processed_total`: Webhook events processed
- `idempotency_conflicts_total`: Idempotency key conflicts

## Security

See [SECURITY.md](SECURITY.md) for detailed security considerations including:
- PCI DSS compliance notes
- Data handling practices
- Logging and monitoring
- Secret management

## Architecture

See [TEACHING.md](TEACHING.md) for detailed explanations of:
- System architecture decisions
- Design patterns used
- Trade-offs and considerations
- Extension guidelines

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details.
