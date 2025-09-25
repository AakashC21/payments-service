package com.payments.config;

import com.payments.middleware.RequestLoggingInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Web configuration for interceptors and other web-related settings.
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {
    
    private final RequestLoggingInterceptor requestLoggingInterceptor;
    
    public WebConfig(RequestLoggingInterceptor requestLoggingInterceptor) {
        this.requestLoggingInterceptor = requestLoggingInterceptor;
    }
    
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(requestLoggingInterceptor);
    }
}

