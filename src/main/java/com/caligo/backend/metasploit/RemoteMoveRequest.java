package com.caligo.backend.metasploit;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RemoteMoveRequest(
        @NotBlank(message = "La ruta remota origen es obligatoria")
        @Size(max = 260, message = "La ruta remota origen es demasiado larga")
        String path,
        @NotBlank(message = "La ruta remota destino es obligatoria")
        @Size(max = 260, message = "La ruta remota destino es demasiado larga")
        String targetPath
) {
}
