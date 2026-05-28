package com.caligo.backend.network;

import com.caligo.backend.audit.AuditEvent;
import com.caligo.backend.audit.AuditEventRepository;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Stream;

@Service
public class VpnControlService {

    private static final Pattern SAFE_PROFILE = Pattern.compile("^[A-Za-z0-9._-]{1,80}$");
    private static final int MAX_OUTPUT = 10_000;

    private final AuditEventRepository auditEvents;
    private final ObjectMapper objectMapper;
    private final Path wireguardDir;
    private final Path openvpnDir;
    private final Path metadataDir;
    private final String helper;
    private final Duration timeout;

    public VpnControlService(
            AuditEventRepository auditEvents,
            ObjectMapper objectMapper,
            @Value("${caligo.network.vpn.wireguard-dir:/etc/caligo/vpn/wireguard}") String wireguardDir,
            @Value("${caligo.network.vpn.openvpn-dir:/etc/caligo/vpn/openvpn}") String openvpnDir,
            @Value("${caligo.network.vpn.metadata-dir:/etc/caligo/vpn/metadata}") String metadataDir,
            @Value("${caligo.network.vpn.helper:/usr/local/sbin/caligo-vpn-control}") String helper,
            @Value("${caligo.network.vpn.command-timeout-seconds:45}") long timeoutSeconds
    ) {
        this.auditEvents = auditEvents;
        this.objectMapper = objectMapper;
        this.wireguardDir = Path.of(wireguardDir);
        this.openvpnDir = Path.of(openvpnDir);
        this.metadataDir = Path.of(metadataDir);
        this.helper = helper;
        this.timeout = Duration.ofSeconds(Math.max(5, timeoutSeconds));
    }

    public Map<String, Object> profiles() {
        List<Map<String, Object>> profiles = discoverProfiles();
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("generatedAt", Instant.now().toString());
        response.put("profiles", profiles);
        response.put("profileCount", profiles.size());
        response.put("providers", providerHints());
        response.put("status", status());
        response.put("configRoots", Map.of(
                "wireguard", wireguardDir.toString(),
                "openvpn", openvpnDir.toString(),
                "metadata", metadataDir.toString()
        ));
        return response;
    }

    public Map<String, Object> status() {
        CommandResult result = run(List.of("sudo", "-n", helper, "status"));
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("generatedAt", Instant.now().toString());
        status.put("helper", helper);
        status.put("available", result.exitCode() == 0);
        status.put("exitCode", result.exitCode());
        status.put("output", sample(result.output()));
        status.put("active", false);
        status.put("profiles", List.of());
        if (result.exitCode() == 0) {
            try {
                Map<String, Object> parsed = objectMapper.readValue(result.output(), new TypeReference<>() {
                });
                status.putAll(parsed);
            } catch (Exception ex) {
                status.put("parseError", ex.getMessage());
            }
        } else if (result.output().contains("interactive authentication")) {
            status.put("message", "Falta NOPASSWD para el helper VPN.");
        }
        return status;
    }

    public Map<String, Object> connect(VpnControlRequest request, String username, String remoteIp) {
        Map<String, Object> profile = requireProfile(request == null ? "" : request.profileId());
        String protocol = String.valueOf(profile.get("protocol"));
        String name = String.valueOf(profile.get("name"));
        auditEvents.save(new AuditEvent(username, "VPN_CONNECT_START", profile.get("id") + " " + profile.get("country"), remoteIp));
        CommandResult result = run(List.of("sudo", "-n", helper, "connect", protocol, name));
        Map<String, Object> response = operationResponse("connect", profile, result);
        auditEvents.save(new AuditEvent(username, result.exitCode() == 0 ? "VPN_CONNECT_SUCCESS" : "VPN_CONNECT_FAILED", String.valueOf(profile.get("id")), remoteIp));
        return response;
    }

    public Map<String, Object> disconnect(VpnControlRequest request, String username, String remoteIp) {
        Optional<Map<String, Object>> profile = Optional.empty();
        String profileId = request == null ? "" : request.profileId();
        List<String> command = new ArrayList<>(List.of("sudo", "-n", helper, "disconnect"));
        if (profileId != null && !profileId.isBlank()) {
            Map<String, Object> selected = requireProfile(profileId);
            profile = Optional.of(selected);
            command.add(String.valueOf(selected.get("protocol")));
            command.add(String.valueOf(selected.get("name")));
        }
        auditEvents.save(new AuditEvent(username, "VPN_DISCONNECT_START", profileId == null || profileId.isBlank() ? "all" : profileId, remoteIp));
        CommandResult result = run(command);
        Map<String, Object> response = operationResponse("disconnect", profile.orElse(null), result);
        auditEvents.save(new AuditEvent(username, result.exitCode() == 0 ? "VPN_DISCONNECT_SUCCESS" : "VPN_DISCONNECT_FAILED", profileId == null || profileId.isBlank() ? "all" : profileId, remoteIp));
        return response;
    }

    private Map<String, Object> operationResponse(String action, Map<String, Object> profile, CommandResult result) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("action", action);
        response.put("status", result.exitCode() == 0 ? "completed" : "failed");
        response.put("exitCode", result.exitCode());
        response.put("output", sample(result.output()));
        response.put("profile", profile);
        response.put("vpn", status());
        return response;
    }

    private Map<String, Object> requireProfile(String profileId) {
        if (profileId == null || profileId.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Selecciona un perfil VPN");
        }
        return discoverProfiles().stream()
                .filter(profile -> profileId.equals(profile.get("id")))
                .findFirst()
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Perfil VPN no encontrado en el servidor"));
    }

    private List<Map<String, Object>> discoverProfiles() {
        List<Map<String, Object>> profiles = new ArrayList<>();
        profiles.addAll(discoverIn(wireguardDir, "wireguard", ".conf"));
        profiles.addAll(discoverIn(openvpnDir, "openvpn", ".ovpn"));
        profiles.sort(Comparator
                .comparing((Map<String, Object> item) -> String.valueOf(item.get("provider")))
                .thenComparing(item -> String.valueOf(item.get("country")))
                .thenComparing(item -> String.valueOf(item.get("label"))));
        return profiles;
    }

    private List<Map<String, Object>> discoverIn(Path root, String protocol, String extension) {
        if (!Files.isDirectory(root)) {
            return List.of();
        }
        try (Stream<Path> stream = Files.list(root)) {
            return stream
                    .filter(Files::isRegularFile)
                    .filter(path -> path.getFileName().toString().endsWith(extension))
                    .map(path -> profileFromPath(path, protocol, extension))
                    .filter(Optional::isPresent)
                    .map(Optional::get)
                    .toList();
        } catch (IOException ex) {
            return List.of();
        }
    }

    private Optional<Map<String, Object>> profileFromPath(Path path, String protocol, String extension) {
        String filename = path.getFileName().toString();
        String name = filename.substring(0, filename.length() - extension.length());
        if (!SAFE_PROFILE.matcher(name).matches()) {
            return Optional.empty();
        }
        Map<String, Object> meta = metadata(name);
        String provider = string(meta.get("provider"), guessProvider(name));
        String country = string(meta.get("country"), guessCountry(name));
        String city = string(meta.get("city"), "");
        String label = string(meta.get("label"), prettyLabel(provider, country, city, name));

        Map<String, Object> row = new LinkedHashMap<>();
        row.put("id", protocol + ":" + name);
        row.put("name", name);
        row.put("label", label);
        row.put("provider", provider);
        row.put("country", country);
        row.put("city", city);
        row.put("protocol", protocol);
        row.put("path", path.toString());
        row.put("description", string(meta.get("description"), "Perfil " + protocol + " cargado desde el servidor."));
        row.put("supportsCountrySelection", true);
        return Optional.of(row);
    }

    private Map<String, Object> metadata(String name) {
        Path file = metadataDir.resolve(name + ".json").normalize();
        if (!file.startsWith(metadataDir) || !Files.isRegularFile(file)) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(Files.readString(file), new TypeReference<>() {
            });
        } catch (Exception ex) {
            return Map.of();
        }
    }

    private List<Map<String, Object>> providerHints() {
        return List.of(
                provider("Mullvad", "WireGuard/OpenVPN", "Privacidad fuerte, cuentas numericas y buen soporte de perfiles por pais."),
                provider("Proton VPN", "WireGuard/OpenVPN", "Proveedor privacy-first con perfiles por pais y Secure Core segun plan."),
                provider("IVPN", "WireGuard/OpenVPN", "Proveedor centrado en minimizacion, transparencia y configuraciones simples.")
        );
    }

    private Map<String, Object> provider(String name, String protocols, String description) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("name", name);
        item.put("protocols", protocols);
        item.put("description", description);
        item.put("status", "requiere perfiles del proveedor en el servidor");
        return item;
    }

    private CommandResult run(List<String> command) {
        Process process = null;
        try {
            process = new ProcessBuilder(command).redirectErrorStream(true).start();
            boolean finished = process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
            String output = readOutput(process);
            if (!finished) {
                process.destroyForcibly();
                return new CommandResult(-1, output + "\nTIMEOUT", true);
            }
            return new CommandResult(process.exitValue(), output, false);
        } catch (IOException ex) {
            return new CommandResult(127, ex.getMessage(), false);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            if (process != null) {
                process.destroyForcibly();
            }
            return new CommandResult(-1, "Proceso interrumpido", true);
        }
    }

    private String readOutput(Process process) throws IOException {
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null && output.length() < MAX_OUTPUT) {
                output.append(line).append('\n');
            }
        }
        return sample(output.toString());
    }

    private String sample(String value) {
        if (value == null) {
            return "";
        }
        return value.length() <= MAX_OUTPUT ? value : value.substring(0, MAX_OUTPUT - 18) + "\n[...truncado...]";
    }

    private String guessProvider(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        if (lower.contains("mullvad") || lower.startsWith("mlvd")) return "Mullvad";
        if (lower.contains("proton")) return "Proton VPN";
        if (lower.contains("ivpn")) return "IVPN";
        return "Custom";
    }

    private String guessCountry(String name) {
        String[] parts = name.split("[-_.]");
        for (String part : parts) {
            if (part.matches("(?i)^[a-z]{2}$")) {
                return part.toUpperCase(Locale.ROOT);
            }
        }
        return "";
    }

    private String prettyLabel(String provider, String country, String city, String name) {
        String location = country == null || country.isBlank() ? name : country + (city == null || city.isBlank() ? "" : " / " + city);
        return provider + " " + location;
    }

    private String string(Object value, String fallback) {
        String text = value == null ? "" : String.valueOf(value).trim();
        return text.isBlank() ? fallback : text;
    }

    private record CommandResult(int exitCode, String output, boolean timedOut) {
    }
}
