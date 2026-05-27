package com.caligo.backend.health;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

@RestController
@RequestMapping("/api/health")
public class HealthController {

    @GetMapping
    public Map<String, Object> publicHealth() {
        return Map.of(
                "status", "ok",
                "service", "back-caligo",
                "checkedAt", Instant.now().toString()
        );
    }

    @GetMapping("/private")
    public Map<String, Object> privateHealth(Authentication authentication) {
        return Map.of(
                "status", "ok",
                "authenticated", true,
                "username", authentication.getName(),
                "checkedAt", Instant.now().toString()
        );
    }
}

