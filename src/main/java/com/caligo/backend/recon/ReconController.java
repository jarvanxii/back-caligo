package com.caligo.backend.recon;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/recon")
public class ReconController {

    private final ReconExecutionService executionService;
    private final ReconReportService reportService;

    public ReconController(ReconExecutionService executionService, ReconReportService reportService) {
        this.executionService = executionService;
        this.reportService = reportService;
    }

    @GetMapping("/nmap/capabilities")
    public Map<String, Object> nmapCapabilities() {
        return executionService.nmapCapabilities();
    }

    @PostMapping("/nmap/scans")
    public Map<String, Object> startNmap(
            @Valid @RequestBody NmapScanRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return executionService.startNmap(request, authentication.getName(), remoteIp(servletRequest));
    }

    @GetMapping("/nmap/scans/{id}")
    public Map<String, Object> nmapJob(@PathVariable UUID id, Authentication authentication) {
        return executionService.job(id, authentication.getName(), "nmap");
    }

    @GetMapping(value = "/nmap/scans/{id}/report.pdf", produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<byte[]> nmapReport(@PathVariable UUID id, Authentication authentication) {
        return report(id, authentication, "nmap");
    }

    @GetMapping("/openvas/capabilities")
    public Map<String, Object> openVasCapabilities() {
        return executionService.openVasCapabilities();
    }

    @PostMapping("/openvas/scans")
    public Map<String, Object> startOpenVas(
            @Valid @RequestBody OpenVasScanRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return executionService.startOpenVas(request, authentication.getName(), remoteIp(servletRequest));
    }

    @GetMapping("/openvas/scans/{id}")
    public Map<String, Object> openVasJob(@PathVariable UUID id, Authentication authentication) {
        return executionService.job(id, authentication.getName(), "openvas");
    }

    @GetMapping(value = "/openvas/scans/{id}/report.pdf", produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<byte[]> openVasReport(@PathVariable UUID id, Authentication authentication) {
        return report(id, authentication, "openvas");
    }

    private ResponseEntity<byte[]> report(UUID id, Authentication authentication, String tool) {
        byte[] pdf = reportService.report(id, authentication.getName(), tool);
        String filename = "caligo-" + tool + "-" + id + ".pdf";
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_PDF)
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment().filename(filename).build().toString())
                .body(pdf);
    }

    private String remoteIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
