package com.caligo.backend.osint;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.util.List;

public record SpiderFootRequest(
        @NotBlank @Size(max = 180) String target,
        @Size(max = 32) String targetType,
        @Size(max = 32) String scanProfile,
        @Size(max = 24) List<String> modules,
        @Size(max = 20) List<String> eventTypes,
        Boolean strictMode,
        @Min(60) @Max(3600) Integer timeoutSeconds,
        Boolean authorized
) {
}
