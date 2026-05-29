package com.caligo.backend.osint;

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
@RequestMapping("/api/osint")
public class OsintToolController {

    private final OsintToolService osintToolService;

    public OsintToolController(OsintToolService osintToolService) {
        this.osintToolService = osintToolService;
    }

    @GetMapping("/capabilities")
    public Map<String, Object> capabilities() {
        return osintToolService.capabilities();
    }

    @PostMapping("/profile-search/search")
    public Map<String, Object> profileSearch(
            @Valid @RequestBody ProfileSearchRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return osintToolService.profileSearch(request, authentication.getName(), remoteIp(servletRequest));
    }

    @PostMapping("/sherlock/runs")
    public Map<String, Object> startSherlock(
            @Valid @RequestBody UsernameOsintRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return osintToolService.startSherlock(request, authentication.getName(), remoteIp(servletRequest));
    }

    @PostMapping("/maigret/runs")
    public Map<String, Object> startMaigret(
            @Valid @RequestBody UsernameOsintRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return osintToolService.startMaigret(request, authentication.getName(), remoteIp(servletRequest));
    }

    @PostMapping("/social-analyzer/runs")
    public Map<String, Object> startSocialAnalyzer(
            @Valid @RequestBody UsernameOsintRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return osintToolService.startSocialAnalyzer(request, authentication.getName(), remoteIp(servletRequest));
    }

    @PostMapping("/holehe/runs")
    public Map<String, Object> startHolehe(
            @Valid @RequestBody EmailOsintRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return osintToolService.startHolehe(request, authentication.getName(), remoteIp(servletRequest));
    }

    @PostMapping("/theharvester/runs")
    public Map<String, Object> startTheHarvester(
            @Valid @RequestBody DomainOsintRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return osintToolService.startTheHarvester(request, authentication.getName(), remoteIp(servletRequest));
    }

    @PostMapping("/git-dumper/runs")
    public Map<String, Object> startGitDumper(
            @Valid @RequestBody GitDumperRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return osintToolService.startGitDumper(request, authentication.getName(), remoteIp(servletRequest));
    }

    @GetMapping("/{tool}/runs")
    public List<Map<String, Object>> runs(@PathVariable String tool, Authentication authentication) {
        return osintToolService.recentJobs(tool, authentication.getName());
    }

    @GetMapping("/{tool}/runs/{id}")
    public Map<String, Object> job(
            @PathVariable String tool,
            @PathVariable UUID id,
            Authentication authentication
    ) {
        return osintToolService.job(id, authentication.getName(), tool);
    }

    private String remoteIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
