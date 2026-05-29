package com.caligo.backend.osint;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PhoneLookupRequest(
        @NotBlank @Size(max = 60) String phone,
        @Size(max = 40) String countryHint,
        Boolean authorized
) {
}
