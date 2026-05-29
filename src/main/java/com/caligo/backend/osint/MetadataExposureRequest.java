package com.caligo.backend.osint;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record MetadataExposureRequest(
        @NotBlank @Size(max = 500) String url,
        Boolean authorized
) {
}
