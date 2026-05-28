package com.caligo.backend.osint;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.util.List;

public record DomainOsintRequest(
        @NotBlank @Size(max = 180) String domain,
        @Size(max = 8) List<String> sources,
        @Min(20) @Max(1000) Integer limit,
        @Min(10) @Max(600) Integer timeoutSeconds
) {
}
