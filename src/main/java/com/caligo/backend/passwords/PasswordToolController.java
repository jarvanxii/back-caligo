package com.caligo.backend.passwords;

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
@RequestMapping("/api/passwords")
public class PasswordToolController {

    private final PasswordToolService passwordToolService;

    public PasswordToolController(PasswordToolService passwordToolService) {
        this.passwordToolService = passwordToolService;
    }

    @GetMapping("/capabilities")
    public Map<String, Object> capabilities() {
        return passwordToolService.capabilities();
    }

    @PostMapping("/identify")
    public Map<String, Object> identify(@Valid @RequestBody HashIdentifyRequest request) {
        return passwordToolService.identify(request);
    }

    @GetMapping("/wordlists")
    public List<Map<String, Object>> wordlists() {
        return passwordToolService.wordlists();
    }

    @PostMapping("/{tool}/runs")
    public Map<String, Object> start(
            @PathVariable String tool,
            @Valid @RequestBody PasswordCrackRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return passwordToolService.startCrack(tool, request, authentication.getName(), remoteIp(servletRequest));
    }

    @PostMapping("/{tool}/generate")
    public Map<String, Object> generate(
            @PathVariable String tool,
            @Valid @RequestBody WordlistGenerateRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return passwordToolService.startGenerator(tool, request, authentication.getName(), remoteIp(servletRequest));
    }

    @GetMapping("/{tool}/runs")
    public List<Map<String, Object>> runs(@PathVariable String tool, Authentication authentication) {
        return passwordToolService.recentJobs(tool, authentication.getName());
    }

    @GetMapping("/{tool}/runs/{id}")
    public Map<String, Object> job(
            @PathVariable String tool,
            @PathVariable UUID id,
            Authentication authentication
    ) {
        return passwordToolService.job(tool, id, authentication.getName());
    }

    private String remoteIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
