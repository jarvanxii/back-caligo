package com.caligo.backend.osint;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PasswordExposureRequest(
        @NotBlank @Size(max = 512) String password,
        Boolean authorized
) {
}
