package com.caligo.backend.urls;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/urls")
public class UrlIntelligenceController {

    private final UrlIntelligenceService intelligenceService;
    private final UrlToolInventoryService toolInventoryService;

    public UrlIntelligenceController(
            UrlIntelligenceService intelligenceService,
            UrlToolInventoryService toolInventoryService
    ) {
        this.intelligenceService = intelligenceService;
        this.toolInventoryService = toolInventoryService;
    }

    @PostMapping("/resolve")
    public Map<String, Object> resolve(
            @Valid @RequestBody UrlAnalysisRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return intelligenceService.resolve(request, authentication.getName(), remoteIp(servletRequest));
    }

    @PostMapping("/dns-resolver")
    public Map<String, Object> dnsResolver(
            @Valid @RequestBody UrlAnalysisRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return intelligenceService.resolve(request, authentication.getName(), remoteIp(servletRequest));
    }

    @PostMapping("/inspector")
    public Map<String, Object> inspector(
            @Valid @RequestBody UrlAnalysisRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return intelligenceService.inspect(request, authentication.getName(), remoteIp(servletRequest));
    }

    @PostMapping("/http-security")
    public Map<String, Object> httpSecurity(
            @Valid @RequestBody UrlAnalysisRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return intelligenceService.httpSecurity(request, authentication.getName(), remoteIp(servletRequest));
    }

    @PostMapping("/tls-certificate")
    public Map<String, Object> tlsCertificate(
            @Valid @RequestBody UrlAnalysisRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return intelligenceService.tlsCertificate(request, authentication.getName(), remoteIp(servletRequest));
    }

    @PostMapping("/reputation")
    public Map<String, Object> reputation(
            @Valid @RequestBody UrlAnalysisRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return intelligenceService.reputation(request, authentication.getName(), remoteIp(servletRequest));
    }

    @PostMapping("/history")
    public Map<String, Object> history(
            @Valid @RequestBody UrlAnalysisRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return intelligenceService.history(request, authentication.getName(), remoteIp(servletRequest));
    }

    @PostMapping("/public-files")
    public Map<String, Object> publicFiles(
            @Valid @RequestBody UrlAnalysisRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return intelligenceService.publicFiles(request, authentication.getName(), remoteIp(servletRequest));
    }

    @PostMapping("/endpoints")
    public Map<String, Object> endpoints(
            @Valid @RequestBody UrlAnalysisRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return intelligenceService.endpoints(request, authentication.getName(), remoteIp(servletRequest));
    }

    @PostMapping("/analyze")
    public Map<String, Object> analyze(
            @Valid @RequestBody UrlAnalysisRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return intelligenceService.analyze(request, authentication.getName(), remoteIp(servletRequest));
    }

    @PostMapping("/intelligent-analysis")
    public Map<String, Object> intelligentAnalysis(
            @Valid @RequestBody UrlAnalysisRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return intelligenceService.analyze(request, authentication.getName(), remoteIp(servletRequest));
    }

    @GetMapping("/tools")
    public Map<String, Object> tools() {
        return toolInventoryService.inventory();
    }

    @GetMapping("/local-tools")
    public Map<String, Object> localTools() {
        return toolInventoryService.inventory();
    }

    @GetMapping("/analyses")
    public List<UrlAnalysisSummary> recent(
            @RequestParam(defaultValue = "10") int limit,
            Authentication authentication
    ) {
        return intelligenceService.recent(authentication.getName(), limit);
    }

    @GetMapping("/analyses/{id}")
    public Map<String, Object> find(
            @PathVariable UUID id,
            Authentication authentication
    ) {
        return intelligenceService.find(id, authentication.getName());
    }

    private String remoteIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
