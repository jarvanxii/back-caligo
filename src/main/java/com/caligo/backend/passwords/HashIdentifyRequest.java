package com.caligo.backend.passwords;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record HashIdentifyRequest(
        @NotBlank @Size(max = 512) String hash
) {
}
