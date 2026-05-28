package com.caligo.backend.osint;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.util.List;

public record ProfileSearchRequest(
        @NotBlank @Size(max = 140) String query,
        @Size(max = 12) List<String> platforms,
        @Size(max = 80) String locationHint,
        @Min(3) @Max(40) Integer maxResults
) {
}
