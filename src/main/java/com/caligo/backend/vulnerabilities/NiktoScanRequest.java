package com.caligo.backend.vulnerabilities;

import jakarta.validation.constraints.Size;

public record NiktoScanRequest(
        @Size(max = 500, message = "El objetivo es demasiado largo")
        String target,
        @Size(max = 24, message = "El tuning es demasiado largo")
        String tuning,
        Integer port,
        Boolean ssl,
        Integer timeoutSeconds
) {
}
