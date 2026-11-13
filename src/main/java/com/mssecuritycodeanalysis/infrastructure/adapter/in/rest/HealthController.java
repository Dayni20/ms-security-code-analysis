package com.mssecuritycodeanalysis.infrastructure.adapter.in.rest;

import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HealthController {

    private final String serviceName;

    public HealthController(@Value("${spring.application.name}") String serviceName) {
        this.serviceName = serviceName;
    }

    @GetMapping("/api/v1/health")
    public Map<String, String> health() {
        return Map.of("status", "UP", "service", serviceName);
    }
}
