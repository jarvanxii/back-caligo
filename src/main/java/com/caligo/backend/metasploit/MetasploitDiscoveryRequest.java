package com.caligo.backend.metasploit;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.util.List;
import java.util.Map;

public record MetasploitDiscoveryRequest(
        @NotBlank(message = "El objetivo es obligatorio")
        @Size(max = 180, message = "El objetivo es demasiado largo")
        String target,
        List<Map<String, Object>> hosts
) {
}
