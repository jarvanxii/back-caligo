package com.caligo.backend.metasploit;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.util.Map;

public record MetasploitExecuteRequest(
        @NotBlank(message = "El tipo de modulo es obligatorio")
        String moduleType,
        @NotBlank(message = "El modulo es obligatorio")
        @Size(max = 240, message = "El modulo es demasiado largo")
        String moduleName,
        @Size(max = 240, message = "El payload es demasiado largo")
        String payload,
        @NotBlank(message = "El objetivo es obligatorio")
        @Size(max = 180, message = "El objetivo es demasiado largo")
        String target,
        Integer rport,
        @Size(max = 120, message = "LHOST es demasiado largo")
        String lhost,
        Integer lport,
        Map<String, Object> options
) {
}
