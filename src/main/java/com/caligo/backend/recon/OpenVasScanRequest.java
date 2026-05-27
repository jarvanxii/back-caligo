package com.caligo.backend.recon;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record OpenVasScanRequest(
        @NotBlank(message = "El objetivo es obligatorio")
        @Size(max = 180, message = "El objetivo es demasiado largo")
        String target,
        String profile,
        String portList,
        String scanner,
        String aliveTest
) {
}
