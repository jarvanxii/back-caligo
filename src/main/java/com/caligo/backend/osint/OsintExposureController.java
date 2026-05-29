package com.caligo.backend.osint;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/osint/exposure")
public class OsintExposureController {

    private final OsintExposureService exposureService;

    public OsintExposureController(OsintExposureService exposureService) {
        this.exposureService = exposureService;
    }

    @GetMapping("/capabilities")
    public Map<String, Object> capabilities() {
        return exposureService.capabilities();
    }

    @PostMapping("/email")
    public Map<String, Object> emailExposure(
            @Valid @RequestBody EmailExposureRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return exposureService.emailExposure(request, authentication.getName(), remoteIp(servletRequest));
    }

    @PostMapping("/phone")
    public Map<String, Object> phoneLookup(
            @Valid @RequestBody PhoneLookupRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return exposureService.phoneLookup(request, authentication.getName(), remoteIp(servletRequest));
    }

    @PostMapping("/domain-contacts")
    public Map<String, Object> domainContacts(
            @Valid @RequestBody DomainContactsRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return exposureService.domainContacts(request, authentication.getName(), remoteIp(servletRequest));
    }

    @PostMapping("/password")
    public Map<String, Object> passwordExposure(
            @Valid @RequestBody PasswordExposureRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return exposureService.passwordExposure(request, authentication.getName(), remoteIp(servletRequest));
    }

    @PostMapping("/public-files")
    public Map<String, Object> publicFiles(
            @Valid @RequestBody PublicFilesRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return exposureService.publicFiles(request, authentication.getName(), remoteIp(servletRequest));
    }

    @PostMapping("/metadata")
    public Map<String, Object> metadataExposure(
            @Valid @RequestBody MetadataExposureRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return exposureService.metadataExposure(request, authentication.getName(), remoteIp(servletRequest));
    }

    private String remoteIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
