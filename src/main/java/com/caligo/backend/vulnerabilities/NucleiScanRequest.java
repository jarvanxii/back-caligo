package com.caligo.backend.vulnerabilities;

import jakarta.validation.constraints.Size;

import java.util.List;

public record NucleiScanRequest(
        @Size(max = 500, message = "El objetivo es demasiado largo")
        String target,
        List<String> severities,
        List<String> tags,
        Integer rateLimit,
        Integer concurrency,
        Integer timeoutSeconds,
        Boolean followRedirects
) {
}
