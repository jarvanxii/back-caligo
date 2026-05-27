package com.caligo.backend.urls;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UrlAnalysisRequest(
        @NotBlank(message = "El objetivo es obligatorio")
        @Size(max = 1000, message = "El objetivo no puede superar 1000 caracteres")
        String target,
        boolean allowPrivateNetworks
) {
}
