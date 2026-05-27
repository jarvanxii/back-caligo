package com.caligo.backend.bruteforce;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/bruteforce")
public class BruteForceController {

    private final HydraService hydraService;

    public BruteForceController(HydraService hydraService) {
        this.hydraService = hydraService;
    }

    @GetMapping("/hydra/capabilities")
    public Map<String, Object> hydraCapabilities() {
        return hydraService.capabilities();
    }

    @PostMapping("/hydra/runs")
    public Map<String, Object> startHydra(
            @Valid @RequestBody HydraScanRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return hydraService.start(request, authentication.getName(), remoteIp(servletRequest));
    }

    @GetMapping("/hydra/runs")
    public List<Map<String, Object>> hydraRuns(Authentication authentication) {
        return hydraService.recentJobs(authentication.getName());
    }

    @GetMapping("/hydra/runs/{id}")
    public Map<String, Object> hydraJob(@PathVariable UUID id, Authentication authentication) {
        return hydraService.job(id, authentication.getName());
    }

    private String remoteIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
