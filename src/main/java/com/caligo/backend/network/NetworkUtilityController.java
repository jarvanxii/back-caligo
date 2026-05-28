package com.caligo.backend.network;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/network")
public class NetworkUtilityController {

    private final NetworkUtilityService networkUtilityService;
    private final VpnControlService vpnControlService;

    public NetworkUtilityController(NetworkUtilityService networkUtilityService, VpnControlService vpnControlService) {
        this.networkUtilityService = networkUtilityService;
        this.vpnControlService = vpnControlService;
    }

    @GetMapping("/identity")
    public Map<String, Object> identity(HttpServletRequest request) {
        return networkUtilityService.identity(request);
    }

    @GetMapping("/vpn/status")
    public Map<String, Object> vpnStatus() {
        return vpnControlService.status();
    }

    @GetMapping("/vpn/profiles")
    public Map<String, Object> vpnProfiles() {
        return vpnControlService.profiles();
    }

    @PostMapping("/vpn/connect")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, Object> connectVpn(
            @Valid @RequestBody VpnControlRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return vpnControlService.connect(request, authentication.getName(), remoteIp(servletRequest));
    }

    @PostMapping("/vpn/disconnect")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, Object> disconnectVpn(
            @Valid @RequestBody(required = false) VpnControlRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return vpnControlService.disconnect(request, authentication.getName(), remoteIp(servletRequest));
    }

    private String remoteIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
