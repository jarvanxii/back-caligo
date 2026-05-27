package com.caligo.backend.metasploit;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RemoteFileReadRequest(
        @NotBlank(message = "La ruta remota es obligatoria")
        @Size(max = 260, message = "La ruta remota es demasiado larga")
        String path,
        Integer maxBytes
) {
}
