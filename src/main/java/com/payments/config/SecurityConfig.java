package com.payments.config;

import com.payments.middleware.JwtAuthenticationFilter;
import com.payments.util.JwtUtil;
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
    public SecurityFilterChain filterChain(HttpSecurity http, JwtUtil jwtUtil) throws Exception {
        http.csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .authorizeHttpRequests(authz -> authz
                // Public endpoints
                .requestMatchers("/api/v1/auth/login").permitAll()
                .requestMatchers("/api/v1/auth/register").permitAll()
                .requestMatchers("/api/v1/webhooks/**").permitAll()
                .requestMatchers("/actuator/health").permitAll()
                .requestMatchers("/actuator/metrics").permitAll()
                .requestMatchers("/swagger-ui/**").permitAll()
                .requestMatchers("/v3/api-docs/**").permitAll()
                // All other endpoints require authentication
                .anyRequest().authenticated()
            )
            .addFilterBefore(new JwtAuthenticationFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);
        
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
     * Password encoder for user credentials.
     * Uses BCrypt for secure password hashing.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
