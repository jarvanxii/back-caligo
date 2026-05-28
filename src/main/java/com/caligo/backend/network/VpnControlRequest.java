package com.caligo.backend.network;

import jakarta.validation.constraints.Size;

public record VpnControlRequest(
        @Size(max = 140, message = "El perfil VPN es demasiado largo")
        String profileId
) {
}
