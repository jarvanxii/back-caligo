package com.caligo.backend.metasploit;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RemoteFileDeleteRequest(
        @NotBlank(message = "La ruta remota es obligatoria")
        @Size(max = 260, message = "La ruta remota es demasiado larga")
        String path,
        Boolean directory
) {
}
