FROM openjdk:17-jdk-slim

# Set working directory
WORKDIR /app

# Install Maven
RUN apt-get update && \
    apt-get install -y maven && \
    rm -rf /var/lib/apt/lists/*

# Copy pom.xml first for better caching
COPY pom.xml ./

# Download dependencies
RUN mvn dependency:go-offline -B

# Copy source code
COPY src ./src

# Build the application
RUN mvn clean package -DskipTests

# Create non-root user
RUN addgroup --system spring && adduser --system spring --ingroup spring

# Change ownership of the app directory
RUN chown -R spring:spring /app
USER spring:spring

# Expose port
EXPOSE 8080

# Run the application
CMD ["java", "-jar", "target/payments-service-1.0.0.jar"]


