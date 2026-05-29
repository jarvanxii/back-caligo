package com.caligo.backend.osint;

import jakarta.validation.constraints.Size;

public record EmailExposureRequest(
        @Size(max = 180) String email,
        @Size(max = 140) String fullName,
        @Size(max = 180) String domain,
        Boolean generateCandidates,
        Boolean authorized
) {
}
