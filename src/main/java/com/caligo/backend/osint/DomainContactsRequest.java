package com.caligo.backend.osint;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.util.List;

public record DomainContactsRequest(
        @NotBlank @Size(max = 180) String domain,
        @Size(max = 12) List<String> paths,
        @Min(5) @Max(45) Integer timeoutSeconds,
        Boolean authorized
) {
}
