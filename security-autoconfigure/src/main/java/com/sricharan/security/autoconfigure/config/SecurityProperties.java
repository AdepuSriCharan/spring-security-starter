package com.sricharan.security.autoconfigure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration properties for the Spring Security Explainer starter.
 */
@ConfigurationProperties(prefix = "security")
public class SecurityProperties {

    /**
     * A list of endpoint ant-matchers that should be publicly accessible
     * without require authentication.
     * Examples: /register, /public/**, /docs
     */
    private List<String> publicEndpoints = new ArrayList<>();

    public List<String> getPublicEndpoints() {
        return publicEndpoints;
    }

    public void setPublicEndpoints(List<String> publicEndpoints) {
        this.publicEndpoints = publicEndpoints;
    }
}
