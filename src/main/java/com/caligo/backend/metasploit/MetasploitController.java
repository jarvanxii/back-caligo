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

    @GetMapping("/module-catalog")
    public Map<String, Object> moduleCatalog(
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

    @PostMapping("/sessions/{id}/workspace")
    public Map<String, Object> sessionWorkspace(
            @PathVariable String id,
            @Valid @RequestBody(required = false) RemotePathRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return metasploitService.sessionWorkspace(id, request, authentication.getName(), remoteIp(servletRequest));
    }

    @PostMapping("/sessions/{id}/fs/list")
    public Map<String, Object> sessionFileList(
            @PathVariable String id,
            @Valid @RequestBody(required = false) RemotePathRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return metasploitService.sessionFileList(id, request, authentication.getName(), remoteIp(servletRequest));
    }

    @PostMapping("/sessions/{id}/fs/read")
    public Map<String, Object> sessionFileRead(
            @PathVariable String id,
            @Valid @RequestBody RemoteFileReadRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return metasploitService.sessionFileRead(id, request, authentication.getName(), remoteIp(servletRequest));
    }

    @PostMapping("/sessions/{id}/fs/mkdir")
    public Map<String, Object> sessionMkdir(
            @PathVariable String id,
            @Valid @RequestBody RemotePathRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return metasploitService.sessionMkdir(id, request, authentication.getName(), remoteIp(servletRequest));
    }

    @PostMapping("/sessions/{id}/fs/delete")
    public Map<String, Object> sessionFileDelete(
            @PathVariable String id,
            @Valid @RequestBody RemoteFileDeleteRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return metasploitService.sessionFileDelete(id, request, authentication.getName(), remoteIp(servletRequest));
    }

    @PostMapping("/sessions/{id}/fs/rename")
    public Map<String, Object> sessionFileRename(
            @PathVariable String id,
            @Valid @RequestBody RemoteMoveRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return metasploitService.sessionFileRename(id, request, authentication.getName(), remoteIp(servletRequest));
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
