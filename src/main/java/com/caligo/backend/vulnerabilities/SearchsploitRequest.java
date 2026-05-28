package com.caligo.backend.vulnerabilities;

import jakarta.validation.constraints.Size;

public record SearchsploitRequest(
        @Size(max = 180, message = "La busqueda es demasiado larga")
        String query,
        @Size(max = 40, message = "El CVE es demasiado largo")
        String cve
) {
}
