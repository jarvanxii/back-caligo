package com.caligo.backend.osint;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.util.List;

public record PublicFilesRequest(
        @NotBlank @Size(max = 220) String target,
        @Size(max = 18) List<String> paths,
        @Min(5) @Max(45) Integer timeoutSeconds,
        Boolean authorized
) {
}
