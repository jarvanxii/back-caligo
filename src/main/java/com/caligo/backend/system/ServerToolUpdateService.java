package com.caligo.backend.system;

import com.caligo.backend.audit.AuditEvent;
import com.caligo.backend.audit.AuditEventRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class ServerToolUpdateService {

    private static final int MAX_OUTPUT_CHARS = 12_000;
    private static final Duration PROBE_TIMEOUT = Duration.ofSeconds(8);
    private static final Pattern VERSION_TOKEN = Pattern.compile("\\b(v?\\d+(?:\\.\\d+)+(?:[-+._a-zA-Z0-9]*)?)\\b");
    private static final String UPDATE_HELPER = "/usr/local/sbin/caligo-tool-update";
    private static final List<ToolDefinition> TOOLS = List.of(
            aptTool("nmap", "nmap", "Nmap", "Reconocimiento", "Escaneo parametrizado de puertos, servicios y scripts NSE.", "nmap --version", "nmap"),
            aptGroupTool("openvas", "gvm-cli", "OpenVAS / GVM", "Reconocimiento", "Motor Greenbone GMP para tareas OpenVAS.", "gvm-cli --version", List.of("gvm", "gvmd", "openvas-scanner", "ospd-openvas", "gvm-tools")),
            aptTool("metasploit", "msfconsole", "Metasploit", "Vulnerabilidades", "Framework RPC para validacion controlada de exploits.", "msfconsole -v", "metasploit-framework"),
            aptTool("hydra", "hydra", "Hydra", "Fuerza bruta", "Validacion de credenciales en servicios de laboratorio.", "hydra -h", "hydra"),
            goTool("nuclei", "nuclei", "Nuclei", "Vulnerabilidades", "Motor de templates para validacion controlada de CVEs y misconfiguraciones.", "nuclei -version", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"),
            gitTool("searchsploit", "searchsploit", "Searchsploit", "Vulnerabilidades", "Busqueda local en Exploit-DB para correlacionar versiones y CVEs.", "searchsploit -h", "/opt/exploitdb"),
            aptTool("nikto", "nikto", "Nikto", "Vulnerabilidades", "Auditoria web de configuraciones, rutas y exposiciones conocidas.", "nikto -Version", "nikto"),
            aptTool("sqlmap", "sqlmap", "sqlmap", "Vulnerabilidades", "Validacion guiada de inyeccion SQL en laboratorios autorizados.", "sqlmap --version", "sqlmap"),
            aptTool("john", "john", "John the Ripper", "Contrasenas", "Auditoria local de hashes y password cracking.", "john", "john"),
            aptTool("hashcat", "hashcat", "Hashcat", "Contrasenas", "Cracking acelerado de hashes cuando hay GPU/CPU disponible.", "hashcat --version", "hashcat"),
            aptTool("hashid", "hashid", "hashID", "Contrasenas", "Identificacion de formatos probables de hash.", "hashid --version", "hashid"),
            aptTool("crunch", "crunch", "Crunch", "Contrasenas", "Generacion controlada de wordlists por longitud y charset.", "crunch --version", "crunch"),
            aptTool("cewl", "cewl", "CeWL", "Contrasenas", "Generacion de wordlists desde contenido web autorizado.", "cewl --version", "cewl"),
            aptTool("curl", "curl", "Curl", "URLs", "Cliente HTTP para inspeccion, cabeceras y pruebas controladas.", "curl --version", "curl"),
            aptTool("openssl", "openssl", "OpenSSL", "URLs", "Inspeccion TLS, certificados y primitivas criptograficas.", "openssl version", "openssl"),
            aptTool("whois", "whois", "Whois", "URLs", "Consulta RDAP/WHOIS de dominios e IPs.", "whois --version", "whois"),
            aptTool("dig", "dig", "dig", "URLs", "Resolucion DNS tecnica desde el servidor.", "dig -v", "dnsutils"),
            aptTool("nslookup", "nslookup", "nslookup", "URLs", "Resolucion DNS compatible y diagnostico rapido.", "nslookup -version", "dnsutils"),
            aptTool("ffuf", "ffuf", "ffuf", "URLs", "Fuzzing web autorizado y descubrimiento de rutas.", "ffuf -V", "ffuf"),
            goTool("httpx", "httpx", "httpx", "URLs", "Fingerprint HTTP masivo y probes de superficie web.", "httpx -version", "github.com/projectdiscovery/httpx/cmd/httpx"),
            goTool("katana", "katana", "Katana", "URLs", "Crawler pasivo/activo para descubrir endpoints.", "katana -version", "github.com/projectdiscovery/katana/cmd/katana"),
            goTool("gau", "gau", "gau", "URLs", "Recoleccion historica de URLs publicas.", "gau --version", "github.com/lc/gau/v2/cmd/gau"),
            goTool("subfinder", "subfinder", "Subfinder", "URLs", "Descubrimiento pasivo de subdominios.", "subfinder -version", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"),
            goTool("amass", "amass", "Amass", "URLs", "Enumeracion OSINT de dominios y superficie externa.", "amass -version", "github.com/owasp-amass/amass/v4/..."),
            backendTool("profile-search", "java", "Caligo People", "OSINT", "Busqueda publica de perfiles sociales por nombre desde el backend.", "java -version"),
            pythonTool("sherlock", "sherlock", "Sherlock", "OSINT", "Enumeracion de usernames en redes sociales y plataformas publicas.", "sherlock --version"),
            pythonTool("maigret", "maigret", "Maigret", "OSINT", "Correlacion OSINT de usernames con scoring y busqueda multi-sitio.", "maigret --version"),
            pythonTool("social-analyzer", "social-analyzer", "Social Analyzer", "OSINT", "Correlacion de nombres y aliases contra perfiles de redes sociales.", "/opt/caligo-pipx/venvs/social-analyzer/bin/python -c 'import importlib.metadata as m; print(m.version(\"social-analyzer\"))'"),
            pythonTool("holehe", "holehe", "Holehe", "OSINT", "Comprobacion de uso publico de emails en servicios online.", "/opt/caligo-pipx/venvs/holehe/bin/python -c 'import importlib.metadata as m; print(m.version(\"holehe\"))'"),
            pythonTool("theharvester", "theHarvester", "theHarvester", "OSINT", "Recoleccion de emails, hosts y fuentes publicas por dominio.", "cd /opt/theHarvester && uv run python -c 'import importlib.metadata as m; print(m.version(\"theharvester\"))'"),
            pythonTool("git-dumper", "git-dumper", "git-dumper", "OSINT", "Recuperacion controlada de repositorios .git expuestos en entornos autorizados.", "git-dumper --help"),
            gitTool("spiderfoot", "spiderfoot", "SpiderFoot", "OSINT", "Correlacion OSINT multi-fuente con modulos configurables.", "spiderfoot --version 2>/dev/null || spiderfoot -h | head -n 1", "/opt/spiderfoot"),
            goTool("trufflehog", "trufflehog", "TruffleHog", "OSINT", "Deteccion de secretos en repositorios, directorios e historicos autorizados.", "trufflehog --version", "github.com/trufflesecurity/trufflehog/v3"),
            aptTool("wireguard", "wg", "WireGuard", "Redes", "Tuneles WireGuard para salida controlada del servidor Caligo.", "wg --version", "wireguard-tools"),
            aptTool("openvpn", "openvpn", "OpenVPN", "Redes", "Cliente OpenVPN para perfiles de proveedores o laboratorios privados.", "openvpn --version", "openvpn"),
            aptTool("resolvconf", "resolvconf", "resolvconf", "Redes", "Gestion de DNS para clientes VPN cuando el perfil lo requiere.", "resolvconf --version", "resolvconf"),
            aptTool("exiftool", "exiftool", "ExifTool", "Esteganografia", "Extraccion y analisis de metadatos en ficheros.", "exiftool -ver", "libimage-exiftool-perl"),
            aptTool("steghide", "steghide", "Steghide", "Esteganografia", "Extraccion e insercion controlada de datos ocultos.", "steghide --version", "steghide"),
            aptTool("binwalk", "binwalk", "Binwalk", "Esteganografia", "Analisis de firmas y contenido embebido.", "binwalk --version", "binwalk"),
            gemTool("zsteg", "zsteg", "zsteg", "Esteganografia", "Deteccion de datos ocultos en imagenes PNG/BMP.", "zsteg --version", "zsteg")
    );

    private final AuditEventRepository auditEvents;
    private final Duration updateTimeout;
    private final ExecutorService ioExecutor = Executors.newCachedThreadPool(runnable -> {
        Thread thread = new Thread(runnable, "caligo-system-tool-io");
        thread.setDaemon(true);
        return thread;
    });

    public ServerToolUpdateService(
            AuditEventRepository auditEvents,
            @Value("${caligo.system.tool-update-timeout-seconds:900}") long updateTimeoutSeconds
    ) {
        this.auditEvents = auditEvents;
        this.updateTimeout = Duration.ofSeconds(Math.max(30, updateTimeoutSeconds));
    }

    public Map<String, Object> inventory() {
        List<Map<String, Object>> tools = TOOLS.stream()
                .map(definition -> snapshot(definition).toMap())
                .toList();

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("generatedAt", Instant.now().toString());
        response.put("toolCount", tools.size());
        response.put("tools", tools);
        return response;
    }

    public Map<String, Object> update(String id, String username, String remoteIp) {
        ToolDefinition definition = findDefinition(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Herramienta no registrada en Caligo"));
        if (definition.updateCommands().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "La herramienta no tiene actualizacion gestionada");
        }

        ToolSnapshot before = snapshot(definition);
        if (!before.installed()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "La herramienta no esta instalada en el servidor");
        }

        Instant startedAt = Instant.now();
        audit(username, "SYSTEM_TOOL_UPDATE_START", definition.id(), remoteIp);

        StringBuilder output = new StringBuilder();
        int exitCode = 0;
        boolean completed = true;
        for (List<String> command : definition.updateCommands()) {
            CommandResult result = runCommand(command, updateTimeout);
            exitCode = result.exitCode();
            appendOutput(output, "$ " + preview(command));
            appendOutput(output, result.output());
            if (result.timedOut()) {
                completed = false;
                appendOutput(output, "TIMEOUT: la actualizacion supero " + updateTimeout.toSeconds() + "s");
                break;
            }
            if (result.exitCode() != 0) {
                completed = false;
                break;
            }
        }

        ToolSnapshot after = snapshot(definition);
        String status = completed ? "completed" : "failed";
        audit(username, completed ? "SYSTEM_TOOL_UPDATE_SUCCESS" : "SYSTEM_TOOL_UPDATE_FAILED", definition.id(), remoteIp);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("id", definition.id());
        response.put("label", definition.label());
        response.put("status", status);
        response.put("startedAt", startedAt.toString());
        response.put("completedAt", Instant.now().toString());
        response.put("beforeVersion", before.version());
        response.put("afterVersion", after.version());
        response.put("changed", !Objects.equals(before.version(), after.version()));
        response.put("exitCode", exitCode);
        response.put("manager", definition.manager());
        response.put("commandPreview", definition.commandPreview());
        response.put("output", sample(output.toString(), MAX_OUTPUT_CHARS));
        response.put("tool", after.toMap());
        return response;
    }

    private Optional<ToolDefinition> findDefinition(String id) {
        String normalized = id == null ? "" : id.toLowerCase(Locale.ROOT).trim();
        return TOOLS.stream().filter(definition -> definition.id().equals(normalized)).findFirst();
    }

    private ToolSnapshot snapshot(ToolDefinition definition) {
        String path = firstNonBlank(runCommand(List.of("sh", "-lc", "command -v " + definition.binary()), PROBE_TIMEOUT).output());
        boolean installed = path != null && !path.isBlank();
        String version = "";
        if (installed) {
            CommandResult versionResult = runCommand(List.of("sh", "-lc", definition.versionCommand()), PROBE_TIMEOUT);
            version = normalizeVersion(bestVersionLine(versionResult.output()));
        }
        return new ToolSnapshot(
                definition.id(),
                definition.binary(),
                definition.label(),
                definition.group(),
                definition.description(),
                installed,
                path == null ? "" : path,
                version,
                definition.manager(),
                installed && !definition.updateCommands().isEmpty(),
                definition.commandPreview(),
                installed ? "ready" : "missing"
        );
    }

    private CommandResult runCommand(List<String> command, Duration timeout) {
        Process process = null;
        StringBuilder output = new StringBuilder();
        try {
            process = new ProcessBuilder(command)
                    .redirectErrorStream(true)
                    .start();
            Process runningProcess = process;
            Future<?> reader = ioExecutor.submit(() -> readProcessOutput(runningProcess, output));
            boolean finished = process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
            if (!finished) {
                process.destroyForcibly();
                try {
                    reader.get(2, TimeUnit.SECONDS);
                } catch (Exception ignored) {
                    // The process is already being killed; partial output is enough.
                }
                return new CommandResult(-1, sample(output.toString(), MAX_OUTPUT_CHARS), true);
            }
            try {
                reader.get(2, TimeUnit.SECONDS);
            } catch (Exception ignored) {
                // Preserve command result even if the reader lags after process exit.
            }
            return new CommandResult(process.exitValue(), sample(output.toString(), MAX_OUTPUT_CHARS), false);
        } catch (IOException ex) {
            return new CommandResult(127, sample(ex.getMessage(), MAX_OUTPUT_CHARS), false);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            if (process != null) {
                process.destroyForcibly();
            }
            return new CommandResult(-1, "Proceso interrumpido", true);
        }
    }

    private void readProcessOutput(Process process, StringBuilder output) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                appendOutput(output, line);
                if (output.length() >= MAX_OUTPUT_CHARS) {
                    appendOutput(output, "[salida truncada]");
                    break;
                }
            }
        } catch (IOException ignored) {
            // Command output is best effort for the settings modal.
        }
    }

    private void audit(String username, String action, String target, String remoteIp) {
        auditEvents.save(new AuditEvent(username, action, target, remoteIp));
    }

    private static synchronized void appendOutput(StringBuilder output, String value) {
        if (value == null || value.isBlank() || output.length() >= MAX_OUTPUT_CHARS) {
            return;
        }
        if (output.length() > 0) {
            output.append('\n');
        }
        output.append(sample(value, MAX_OUTPUT_CHARS - output.length()));
    }

    private static String firstNonBlank(String output) {
        if (output == null) {
            return null;
        }
        for (String line : output.split("\\R")) {
            String trimmed = line.trim();
            if (!trimmed.isBlank()) {
                return trimmed;
            }
        }
        return null;
    }

    private static String bestVersionLine(String output) {
        if (output == null) {
            return null;
        }
        List<String> lines = output.lines()
                .map(ServerToolUpdateService::stripAnsi)
                .map(String::trim)
                .filter(line -> !line.isBlank())
                .toList();
        if (lines.isEmpty()) {
            return null;
        }
        return lines.stream()
                .filter(line -> line.matches("(?i).*version.*\\d.*"))
                .findFirst()
                .or(() -> lines.stream().filter(line -> line.matches(".*\\d+\\.\\d+.*")).findFirst())
                .orElse(lines.getFirst());
    }

    private static String stripAnsi(String value) {
        return value == null ? "" : value.replaceAll("\\u001B\\[[;\\d]*m", "");
    }

    private static String normalizeVersion(String line) {
        if (line == null) {
            return "";
        }
        String cleaned = stripAnsi(line)
                .replaceFirst("^\\[[A-Z]+]\\s*", "")
                .replaceAll("\\s+", " ")
                .trim();
        Matcher matcher = VERSION_TOKEN.matcher(cleaned);
        if (matcher.find()) {
            return matcher.group(1).replaceAll("[.,;:]+$", "");
        }
        return inlineSample(cleaned, 150);
    }

    private static String sample(String value, int maxChars) {
        if (value == null) {
            return "";
        }
        if (value.length() <= maxChars) {
            return value;
        }
        return value.substring(0, Math.max(0, maxChars - 18)) + "\n[...truncado...]";
    }

    private static String inlineSample(String value, int maxChars) {
        if (value == null || value.length() <= maxChars) {
            return value == null ? "" : value;
        }
        return value.substring(0, Math.max(0, maxChars - 3)) + "...";
    }

    private static ToolDefinition aptTool(
            String id,
            String binary,
            String label,
            String group,
            String description,
            String versionCommand,
            String packageName
    ) {
        return aptGroupTool(id, binary, label, group, description, versionCommand, List.of(packageName));
    }

    private static ToolDefinition aptGroupTool(
            String id,
            String binary,
            String label,
            String group,
            String description,
            String versionCommand,
            List<String> packageNames
    ) {
        return new ToolDefinition(
                id,
                binary,
                label,
                group,
                description,
                versionCommand,
                "apt",
                helperUpdate(id)
        );
    }

    private static ToolDefinition goTool(
            String id,
            String binary,
            String label,
            String group,
            String description,
            String versionCommand,
            String module
    ) {
        return new ToolDefinition(
                id,
                binary,
                label,
                group,
                description,
                versionCommand,
                "go",
                helperUpdate(id)
        );
    }

    private static ToolDefinition gitTool(
            String id,
            String binary,
            String label,
            String group,
            String description,
            String versionCommand,
            String repositoryPath
    ) {
        return new ToolDefinition(
                id,
                binary,
                label,
                group,
                description,
                versionCommand,
                "git",
                helperUpdate(id)
        );
    }

    private static ToolDefinition gemTool(
            String id,
            String binary,
            String label,
            String group,
            String description,
            String versionCommand,
            String gemName
    ) {
        return new ToolDefinition(
                id,
                binary,
                label,
                group,
                description,
                versionCommand,
                "gem",
                helperUpdate(id)
        );
    }

    private static ToolDefinition pythonTool(
            String id,
            String binary,
            String label,
            String group,
            String description,
            String versionCommand
    ) {
        return new ToolDefinition(
                id,
                binary,
                label,
                group,
                description,
                versionCommand,
                "pipx",
                helperUpdate(id)
        );
    }

    private static ToolDefinition backendTool(
            String id,
            String binary,
            String label,
            String group,
            String description,
            String versionCommand
    ) {
        return new ToolDefinition(
                id,
                binary,
                label,
                group,
                description,
                versionCommand,
                "backend",
                List.of()
        );
    }

    private static String preview(List<String> command) {
        return String.join(" ", command);
    }

    private static List<List<String>> helperUpdate(String id) {
        return List.of(List.of("sudo", "-n", UPDATE_HELPER, id));
    }

    private record ToolDefinition(
            String id,
            String binary,
            String label,
            String group,
            String description,
            String versionCommand,
            String manager,
            List<List<String>> updateCommands
    ) {
        String commandPreview() {
            return updateCommands.stream()
                    .map(ServerToolUpdateService::preview)
                    .reduce((left, right) -> left + " && " + right)
                    .orElse("");
        }
    }

    private record ToolSnapshot(
            String id,
            String binary,
            String label,
            String group,
            String description,
            boolean installed,
            String path,
            String version,
            String manager,
            boolean updateSupported,
            String updateCommandPreview,
            String status
    ) {
        Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("id", id);
            map.put("binary", binary);
            map.put("label", label);
            map.put("group", group);
            map.put("description", description);
            map.put("installed", installed);
            map.put("path", path);
            map.put("version", version);
            map.put("manager", manager);
            map.put("updateSupported", updateSupported);
            map.put("updateCommandPreview", updateCommandPreview);
            map.put("status", status);
            return map;
        }
    }

    private record CommandResult(int exitCode, String output, boolean timedOut) {
    }
}
