package com.caligo.backend.osint;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UsernameOsintRequest(
        @NotBlank @Size(max = 140) String query,
        @Min(20) @Max(1000) Integer topSites,
        @Min(5) @Max(120) Integer timeoutSeconds,
        Boolean deepMode
) {
}
