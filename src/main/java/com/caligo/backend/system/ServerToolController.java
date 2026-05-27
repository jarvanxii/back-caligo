package com.caligo.backend.system;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/system")
public class ServerToolController {

    private final ServerToolUpdateService toolUpdateService;

    public ServerToolController(ServerToolUpdateService toolUpdateService) {
        this.toolUpdateService = toolUpdateService;
    }

    @GetMapping("/tools")
    public Map<String, Object> tools() {
        return toolUpdateService.inventory();
    }

    @PostMapping("/tools/{id}/update")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, Object> update(
            @PathVariable String id,
            Authentication authentication,
            HttpServletRequest request
    ) {
        return toolUpdateService.update(id, authentication.getName(), remoteIp(request));
    }

    private String remoteIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
