package com.caligo.backend.urls;

import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Service
public class UrlToolInventoryService {

    private static final List<ToolDefinition> TOOLS = List.of(
            new ToolDefinition("curl", "HTTP", "Cliente HTTP auxiliar para comprobaciones manuales."),
            new ToolDefinition("openssl", "TLS", "Inspeccion de certificados, cadenas y handshakes TLS."),
            new ToolDefinition("whois", "Registro", "Consulta registral clasica cuando RDAP no sea suficiente."),
            new ToolDefinition("dig", "DNS", "Resolucion DNS avanzada desde el servidor."),
            new ToolDefinition("nslookup", "DNS", "Resolucion DNS basica disponible en muchos sistemas."),
            new ToolDefinition("httpx", "Web recon", "Validacion masiva de hosts activos y metadatos HTTP."),
            new ToolDefinition("nuclei", "Plantillas", "Checks por plantillas en objetivos autorizados."),
            new ToolDefinition("katana", "Crawler", "Crawling controlado y descubrimiento de endpoints."),
            new ToolDefinition("gau", "Historial", "Extraccion de URLs conocidas desde fuentes historicas."),
            new ToolDefinition("subfinder", "Subdominios", "Enumeracion pasiva de subdominios."),
            new ToolDefinition("amass", "Superficie", "Mapeo amplio de activos y relaciones."),
            new ToolDefinition("ffuf", "Fuzzing", "Fuzzing web controlado con wordlists.")
    );

    public Map<String, Object> inventory() {
        List<Map<String, Object>> tools = new ArrayList<>();
        for (ToolDefinition tool : TOOLS) {
            tools.add(probe(tool));
        }

        return Map.of(
                "mode", "local-server",
                "timeoutMs", Duration.ofSeconds(2).toMillis(),
                "tools", tools
        );
    }

    private Map<String, Object> probe(ToolDefinition tool) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("name", tool.name());
        result.put("group", tool.group());
        result.put("description", tool.description());
        result.put("installed", false);
        result.put("path", null);

        List<String> command = lookupCommand(tool.name());
        try {
            Process process = new ProcessBuilder(command)
                    .redirectErrorStream(true)
                    .start();
            boolean finished = process.waitFor(2, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                result.put("error", "timeout");
                return result;
            }

            String output = new String(process.getInputStream().readAllBytes()).trim();
            if (process.exitValue() == 0 && !output.isBlank()) {
                result.put("installed", true);
                result.put("path", output.lines().findFirst().orElse(null));
            } else {
                result.put("error", output.isBlank() ? "not_found" : output);
            }
        } catch (IOException ex) {
            result.put("error", ex.getMessage());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            result.put("error", "interrupted");
        }

        return result;
    }

    private List<String> lookupCommand(String name) {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.contains("win")) {
            return List.of("where.exe", name);
        }
        return List.of("sh", "-lc", "command -v " + shellQuote(name));
    }

    private String shellQuote(String value) {
        return "'" + value.replace("'", "'\"'\"'") + "'";
    }

    private record ToolDefinition(String name, String group, String description) {
    }
}
