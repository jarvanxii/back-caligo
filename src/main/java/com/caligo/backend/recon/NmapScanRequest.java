package com.caligo.backend.recon;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record NmapScanRequest(
        @NotBlank(message = "El objetivo es obligatorio")
        @Size(max = 180, message = "El objetivo es demasiado largo")
        String target,
        String profile,
        String scanType,
        String portMode,
        @Size(max = 240, message = "La lista de puertos es demasiado larga")
        String ports,
        @Min(value = 10, message = "topPorts minimo: 10")
        @Max(value = 5000, message = "topPorts maximo: 5000")
        Integer topPorts,
        String timing,
        Boolean serviceDetection,
        Boolean defaultScripts,
        Boolean osDetection,
        Boolean traceroute,
        Boolean noPing,
        @Min(value = 0, message = "maxRetries minimo: 0")
        @Max(value = 10, message = "maxRetries maximo: 10")
        Integer maxRetries
) {
}
