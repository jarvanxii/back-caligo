package com.caligo.backend.recon;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.util.List;

public record ReconCliScanRequest(
        @NotBlank(message = "El objetivo es obligatorio")
        @Size(max = 500, message = "El objetivo es demasiado largo")
        String target,
        String mode,
        String wordlist,
        String nameServer,
        List<String> subdomains,
        Boolean authorized,
        Boolean subsOnly,
        Boolean bruteForce,
        Boolean zoneTransfer,
        Boolean reverseLookup,
        Boolean crtsh,
        Boolean bing,
        Boolean yandex,
        Boolean whois,
        Boolean dnssec,
        Boolean tcp,
        Boolean wide,
        Boolean connect,
        Boolean aliveOnly,
        @Min(value = 1, message = "threads mínimo: 1")
        @Max(value = 80, message = "threads máximo: 80")
        Integer threads,
        @Min(value = 1, message = "count mínimo: 1")
        @Max(value = 10, message = "count máximo: 10")
        Integer count,
        @Min(value = 20, message = "intervalMillis mínimo: 20")
        @Max(value = 5000, message = "intervalMillis máximo: 5000")
        Integer intervalMillis,
        @Min(value = 100, message = "timeoutMillis mínimo: 100")
        @Max(value = 10000, message = "timeoutMillis máximo: 10000")
        Integer timeoutMillis,
        @Min(value = 5, message = "timeoutSeconds mínimo: 5")
        @Max(value = 1800, message = "timeoutSeconds máximo: 1800")
        Integer timeoutSeconds
) {
}
