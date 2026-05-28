package com.caligo.backend.osint;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record EmailOsintRequest(
        @NotBlank @Email @Size(max = 180) String email,
        @Min(5) @Max(120) Integer timeoutSeconds,
        Boolean onlyUsed
) {
}
