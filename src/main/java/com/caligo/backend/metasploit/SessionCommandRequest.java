package com.caligo.backend.metasploit;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record SessionCommandRequest(
        @NotBlank(message = "El comando es obligatorio")
        @Size(max = 500, message = "El comando es demasiado largo")
        String command
) {
}
