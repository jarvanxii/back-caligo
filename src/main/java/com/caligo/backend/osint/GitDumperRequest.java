package com.caligo.backend.osint;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.util.List;

public record GitDumperRequest(
        @NotBlank @Size(max = 360) String url,
        Boolean appendGitPath,
        @Min(1) @Max(40) Integer jobs,
        @Min(0) @Max(10) Integer retry,
        @Min(5) @Max(900) Integer timeoutSeconds,
        @Size(max = 180) String userAgent,
        @Size(max = 240) String proxy,
        @Size(max = 8) List<@Size(max = 180) String> headers,
        @Size(max = 8) List<@Size(max = 90) String> branches,
        Boolean authorized
) {
}
