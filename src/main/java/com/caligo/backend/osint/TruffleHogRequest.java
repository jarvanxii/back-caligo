package com.caligo.backend.osint;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.util.List;

public record TruffleHogRequest(
        @NotBlank @Size(max = 24) String sourceType,
        @NotBlank @Size(max = 500) String target,
        @Size(max = 40) String results,
        @Size(max = 120) String branch,
        @Min(1) @Max(5000) Integer maxDepth,
        @Min(1) @Max(64) Integer concurrency,
        @Size(max = 16) List<String> includePaths,
        @Size(max = 16) List<String> excludePaths,
        Boolean noVerification,
        Boolean filterEntropy,
        Boolean scanEntireChunk,
        @Min(30) @Max(3600) Integer timeoutSeconds,
        Boolean authorized
) {
}
