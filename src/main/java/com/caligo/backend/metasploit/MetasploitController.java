package com.caligo.backend.metasploit;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/metasploit")
public class MetasploitController {

    private final MetasploitService metasploitService;

    public MetasploitController(MetasploitService metasploitService) {
        this.metasploitService = metasploitService;
    }

    @GetMapping("/capabilities")
    public Map<String, Object> capabilities() {
        return metasploitService.capabilities();
    }

    @PostMapping("/recommendations")
    public Map<String, Object> recommendations(@Valid @RequestBody MetasploitDiscoveryRequest request) {
        return metasploitService.recommendations(request);
    }

    @GetMapping("/modules/search")
    public Map<String, Object> search(
            @RequestParam(defaultValue = "") String query,
            @RequestParam(defaultValue = "") String type
    ) {
        return metasploitService.search(query, type);
    }

    @GetMapping("/module-search")
    public Map<String, Object> moduleSearch(
            @RequestParam(defaultValue = "") String query,
            @RequestParam(defaultValue = "") String type
    ) {
        return metasploitService.search(query, type);
    }

    @GetMapping("/modules/info")
    public Map<String, Object> moduleInfo(
            @RequestParam String type,
            @RequestParam String name
    ) {
        return metasploitService.moduleInfo(type, name);
    }

    @PostMapping("/modules/execute")
    public Map<String, Object> execute(
            @Valid @RequestBody MetasploitExecuteRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return metasploitService.execute(request, authentication.getName(), remoteIp(servletRequest));
    }

    @GetMapping("/jobs")
    public Map<String, Object> jobs() {
        return metasploitService.jobs();
    }

    @GetMapping("/jobs/{id}")
    public Map<String, Object> job(@PathVariable UUID id, Authentication authentication) {
        return metasploitService.job(id, authentication.getName());
    }

    @GetMapping("/sessions")
    public Map<String, Object> sessions() {
        return metasploitService.sessions();
    }

    @PostMapping("/sessions/{id}/command")
    public Map<String, Object> sessionCommand(
            @PathVariable String id,
            @Valid @RequestBody SessionCommandRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return metasploitService.sessionCommand(id, request, authentication.getName(), remoteIp(servletRequest));
    }

    @DeleteMapping("/sessions/{id}")
    public Map<String, Object> stopSession(
            @PathVariable String id,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return metasploitService.stopSession(id, authentication.getName(), remoteIp(servletRequest));
    }

    private String remoteIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
