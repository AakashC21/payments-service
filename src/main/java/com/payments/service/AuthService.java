package com.payments.service;

import com.payments.model.dto.LoginRequest;
import com.payments.model.dto.LoginResponse;
import com.payments.model.entity.User;
import com.payments.repository.UserRepository;
import com.payments.util.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * Service for authentication operations.
 */
@Service
@Transactional
public class AuthService {
    
    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);
    
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    
    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }
    
    public LoginResponse authenticateUser(LoginRequest loginRequest) {
        logger.info("Authenticating user: {}", loginRequest.getEmail());
        
        User user = userRepository.findByEmail(loginRequest.getEmail())
            .orElseThrow(() -> new RuntimeException("Invalid credentials"));
        
        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid credentials");
        }
        
        String token = jwtUtil.generateToken(user.getEmail(), user.getId());
        
        return new LoginResponse(token, user.getId(), user.getEmail());
    }
    
    public User createUser(String email, String password, String firstName, String lastName) {
        logger.info("Creating user: {}", email);
        
        if (userRepository.existsByEmail(email)) {
            throw new RuntimeException("User already exists");
        }
        
        User user = new User();
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setActive(true);
        user.setCreatedAt(LocalDateTime.now());
        
        return userRepository.save(user);
    }
}
