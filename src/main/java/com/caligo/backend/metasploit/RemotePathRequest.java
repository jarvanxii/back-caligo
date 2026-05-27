package com.caligo.backend.metasploit;

import jakarta.validation.constraints.Size;

public record RemotePathRequest(
        @Size(max = 260, message = "La ruta remota es demasiado larga")
        String path
) {
}
