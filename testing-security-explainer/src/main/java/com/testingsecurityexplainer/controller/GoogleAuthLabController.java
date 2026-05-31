package com.testingsecurityexplainer.controller;

import com.sricharan.security.autoconfigure.config.SecurityProperties;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Small public config endpoint for the Google sign-in test page.
 *
 * <p>The static page uses this to decide whether it can render the Google Identity
 * Services button or should fall back to manual ID-token paste mode.
 */
@RestController
@RequestMapping(value = "/google-auth-lab", produces = MediaType.APPLICATION_JSON_VALUE)
public class GoogleAuthLabController {

    private final SecurityProperties securityProperties;

    public GoogleAuthLabController(SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    @GetMapping("/config")
    public Map<String, Object> config() {
        Map<String, Object> body = new LinkedHashMap<>();
        SecurityProperties.Google google = securityProperties.getGoogle();
        body.put("enabled", google.isEnabled());
        body.put("clientIds", google.getClientIds());
        body.put("issuerUri", google.getIssuerUri());
        body.put("autoLinkByEmail", google.isAutoLinkByEmail());
        return body;
    }
}
