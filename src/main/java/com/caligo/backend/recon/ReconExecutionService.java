package com.caligo.backend.recon;

import com.caligo.backend.audit.AuditEvent;
import com.caligo.backend.audit.AuditEventRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PreDestroy;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class ReconExecutionService {

    private static final Pattern SAFE_TARGET = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,179}$");
    private static final Pattern SAFE_PORTS = Pattern.compile("^[0-9,TU:,-]{1,240}$");
    private static final Pattern IPV4 = Pattern.compile("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");
    private static final Pattern NMAP_PROGRESS = Pattern.compile("About\\s+(\\d+(?:\\.\\d+)?)%\\s+done", Pattern.CASE_INSENSITIVE);

    private final ToolExecutionJobRepository jobs;
    private final AuditEventRepository auditEvents;
    private final ObjectMapper objectMapper;
    private final ExecutorService executor;
    private final Map<UUID, RuntimeLog> runtimeLogs = new ConcurrentHashMap<>();

    private final String nmapBinary;
    private final String gvmCliBinary;
    private final String gvmSocket;
    private final String gvmUsername;
    private final String gvmPassword;
    private final boolean allowExternalTargets;
    private final int maxOutputBytes;
    private final long nmapTimeoutSeconds;
    private final long openVasPollSeconds;
    private final long openVasTimeoutSeconds;

    public ReconExecutionService(
            ToolExecutionJobRepository jobs,
            AuditEventRepository auditEvents,
            ObjectMapper objectMapper,
            @Value("${caligo.recon.nmap.binary:nmap}") String nmapBinary,
            @Value("${caligo.recon.openvas.gvm-cli:gvm-cli}") String gvmCliBinary,
            @Value("${caligo.recon.openvas.socket:/run/gvmd/gvmd.sock}") String gvmSocket,
            @Value("${caligo.recon.openvas.username:}") String gvmUsername,
            @Value("${caligo.recon.openvas.password:}") String gvmPassword,
            @Value("${caligo.recon.allow-external-targets:false}") boolean allowExternalTargets,
            @Value("${caligo.recon.max-output-bytes:1048576}") int maxOutputBytes,
            @Value("${caligo.recon.nmap.timeout-seconds:900}") long nmapTimeoutSeconds,
            @Value("${caligo.recon.openvas.poll-seconds:10}") long openVasPollSeconds,
            @Value("${caligo.recon.openvas.timeout-seconds:7200}") long openVasTimeoutSeconds
    ) {
        this.jobs = jobs;
        this.auditEvents = auditEvents;
        this.objectMapper = objectMapper;
        this.nmapBinary = nmapBinary;
        this.gvmCliBinary = gvmCliBinary;
        this.gvmSocket = gvmSocket;
        this.gvmUsername = gvmUsername;
        this.gvmPassword = gvmPassword;
        this.allowExternalTargets = allowExternalTargets;
        this.maxOutputBytes = maxOutputBytes;
        this.nmapTimeoutSeconds = nmapTimeoutSeconds;
        this.openVasPollSeconds = openVasPollSeconds;
        this.openVasTimeoutSeconds = openVasTimeoutSeconds;
        this.executor = Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "caligo-recon-worker");
            thread.setDaemon(true);
            return thread;
        });
    }

    @PreDestroy
    void shutdown() {
        executor.shutdownNow();
    }

    public Map<String, Object> nmapCapabilities() {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("tool", "nmap");
        response.put("available", commandAvailable(nmapBinary));
        response.put("binary", nmapBinary);
        response.put("scope", scopePolicy());
        response.put("profiles", List.of(
                option("quick", "Rapido", "Top 100 TCP, baja friccion para una primera lectura."),
                option("standard", "Estandar", "Top 1000 TCP con deteccion de servicios."),
                option("service", "Servicios", "Puertos concretos con versiones y scripts por defecto opcionales."),
                option("web", "Web expuesta", "Puertos web comunes con huellas HTTP seguras."),
                option("discovery", "Discovery", "Ping sweep sin escaneo de puertos."),
                option("udp-light", "UDP ligero", "Top 50 UDP para senales basicas.")
        ));
        response.put("scanTypes", List.of(
                option("tcp-connect", "TCP connect", "No necesita privilegios elevados."),
                option("udp", "UDP", "Mas lento; usar con rangos pequenos.")
        ));
        response.put("portModes", List.of(
                option("top", "Top ports", "Usa --top-ports."),
                option("custom", "Puertos concretos", "Lista como 22,80,443 o 1-1024."),
                option("all", "Todos TCP", "Usa -p-; puede tardar mucho.")
        ));
        response.put("timings", List.of("T2", "T3", "T4"));
        Map<String, Object> defaults = new LinkedHashMap<>();
        defaults.put("target", "192.168.0.1");
        defaults.put("profile", "standard");
        defaults.put("scanType", "tcp-connect");
        defaults.put("portMode", "top");
        defaults.put("topPorts", 1000);
        defaults.put("timing", "T3");
        defaults.put("serviceDetection", true);
        defaults.put("defaultScripts", false);
        defaults.put("osDetection", false);
        defaults.put("traceroute", false);
        defaults.put("noPing", false);
        defaults.put("maxRetries", 2);
        response.put("defaults", defaults);
        return response;
    }

    public Map<String, Object> openVasCapabilities() {
        boolean cliAvailable = commandAvailable(gvmCliBinary);
        boolean socketAvailable = Files.exists(Path.of(gvmSocket));
        boolean credentialsConfigured = hasText(gvmUsername) && hasText(gvmPassword);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("tool", "openvas");
        response.put("available", false);
        response.put("cliAvailable", cliAvailable);
        response.put("socketAvailable", socketAvailable);
        response.put("credentialsConfigured", credentialsConfigured);
        response.put("socket", gvmSocket);
        response.put("scope", scopePolicy());
        response.put("profiles", fallbackOpenVasProfiles());
        response.put("portLists", fallbackOpenVasPortLists());
        response.put("scanners", fallbackOpenVasScanners());
        response.put("aliveTests", List.of(
                option("Scan Config Default", "Por defecto del perfil", "Usa el alive test recomendado por la configuracion."),
                option("ICMP Ping", "ICMP", "Rapido si ICMP esta permitido."),
                option("TCP-ACK Service Ping", "TCP ACK", "Util cuando ICMP esta filtrado."),
                option("Consider Alive", "Considerar vivo", "Para laboratorios donde sabes que el objetivo existe.")
        ));
        Map<String, Object> defaults = new LinkedHashMap<>();
        defaults.put("target", "192.168.0.50");
        defaults.put("profile", "Full and fast");
        defaults.put("portList", "All IANA assigned TCP");
        defaults.put("scanner", "OpenVAS Default");
        defaults.put("aliveTest", "Scan Config Default");
        response.put("defaults", defaults);

        if (!cliAvailable) {
            response.put("setupState", "gvm-cli-no-detectado");
            response.put("message", "Instala gvm-tools en el servidor del backend.");
            return response;
        }
        if (!socketAvailable) {
            response.put("setupState", "gvmd-socket-no-disponible");
            response.put("message", "gvmd no esta listo o falta completar la inicializacion/feed de GVM.");
            return response;
        }
        if (!credentialsConfigured) {
            response.put("setupState", "credenciales-gmp-pendientes");
            response.put("message", "Configura CALIGO_GVM_USERNAME y CALIGO_GVM_PASSWORD en el entorno del backend.");
            return response;
        }

        try {
            String versionXml = runGvmXml("<get_version/>", 30);
            response.put("version", text(first(parseXml(versionXml), "version")));
            List<Map<String, String>> profiles = gvmEntities("<get_configs/>", "config");
            List<Map<String, String>> portLists = gvmEntities("<get_port_lists/>", "port_list");
            List<Map<String, String>> scanners = usableOpenVasScanners(gvmEntities("<get_scanners/>", "scanner"));
            response.put("profiles", profiles);
            response.put("portLists", portLists);
            response.put("scanners", scanners);
            response.put("defaults", openVasDefaults(profiles, portLists, scanners));
            if (profiles.isEmpty() || portLists.isEmpty() || scanners.isEmpty()) {
                response.put("available", false);
                response.put("setupState", "gvmd-data-incompleto");
                response.put("message", "GVM responde, pero faltan scan configs, port lists o scanner OpenVAS. Ejecuta la sincronizacion/rebuild de datos GVMD.");
                return response;
            }
            response.put("available", true);
            response.put("setupState", "ready");
            response.put("message", "GVM responde por socket GMP.");
        } catch (Exception ex) {
            response.put("setupState", "gvm-no-responde");
            response.put("message", sample(ex.getMessage(), 500));
        }
        return response;
    }

    public Map<String, Object> startNmap(NmapScanRequest request, String username, String remoteIp) {
        if (!commandAvailable(nmapBinary)) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Nmap no esta instalado o no esta en PATH");
        }
        String target = sanitizeTarget(request.target());
        List<String> command = buildNmapCommand(request, target);
        ToolExecutionJob job = jobs.save(new ToolExecutionJob(
                username,
                "nmap",
                target,
                writeJson(request),
                preview(command)
        ));
        RuntimeLog log = new RuntimeLog();
        runtimeLogs.put(job.getId(), log);
        auditEvents.save(new AuditEvent(username, "NMAP_SCAN_START", target, remoteIp));
        CompletableFuture.runAsync(() -> runNmap(job.getId(), command, log), executor);
        return job(job.getId(), username, "nmap");
    }

    public Map<String, Object> startOpenVas(OpenVasScanRequest request, String username, String remoteIp) {
        String target = sanitizeTarget(request.target());
        Map<String, Object> capabilities = openVasCapabilities();
        if (!Boolean.TRUE.equals(capabilities.get("available"))) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, String.valueOf(capabilities.get("message")));
        }
        ToolExecutionJob job = jobs.save(new ToolExecutionJob(
                username,
                "openvas",
                target,
                writeJson(request),
                "gvm-cli socket GMP task"
        ));
        RuntimeLog log = new RuntimeLog();
        runtimeLogs.put(job.getId(), log);
        auditEvents.save(new AuditEvent(username, "OPENVAS_SCAN_START", target, remoteIp));
        CompletableFuture.runAsync(() -> runOpenVas(job.getId(), request, target, log), executor);
        return job(job.getId(), username, "openvas");
    }

    public Map<String, Object> job(UUID id, String username, String expectedTool) {
        ToolExecutionJob job = jobs.findById(id)
                .filter(item -> username.equals(item.getUsername()))
                .filter(item -> expectedTool.equals(item.getTool()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Job no encontrado"));
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("id", job.getId());
        response.put("tool", job.getTool());
        response.put("target", job.getTarget());
        response.put("status", job.getStatus());
        response.put("progress", job.getProgress());
        response.put("phase", job.getPhase());
        response.put("createdAt", string(job.getCreatedAt()));
        response.put("startedAt", string(job.getStartedAt()));
        response.put("completedAt", string(job.getCompletedAt()));
        response.put("durationMs", durationMs(job.getStartedAt(), job.getCompletedAt()));
        response.put("parameters", readJson(job.getParametersJson()));
        response.put("result", readJson(job.getResultJson()));
        response.put("error", job.getErrorMessage());
        response.put("command", job.getCommandPreview());
        RuntimeLog log = runtimeLogs.get(job.getId());
        response.put("logs", log == null ? List.of() : log.snapshot());
        return response;
    }

    private void runNmap(UUID jobId, List<String> command, RuntimeLog log) {
        update(jobId, job -> job.markRunning("Lanzando nmap"));
        try {
            Process process = new ProcessBuilder(command)
                    .redirectErrorStream(false)
                    .start();
            update(jobId, job -> job.updateProgress(5, "Escaneo en curso"));

            Future<String> stdout = executor.submit(readStream(process.getInputStream(), line -> {
            }));
            Future<String> stderr = executor.submit(readStream(process.getErrorStream(), line -> {
                log.add(line);
                Matcher matcher = NMAP_PROGRESS.matcher(line);
                if (matcher.find()) {
                    int value = Math.max(5, Math.min(99, (int) Math.floor(Double.parseDouble(matcher.group(1)))));
                    update(jobId, job -> job.updateProgress(value, "Escaneo en curso"));
                }
            }));

            boolean finished = process.waitFor(nmapTimeoutSeconds, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                throw new IllegalStateException("Tiempo maximo de ejecucion superado");
            }

            int exitCode = process.exitValue();
            String xml = stdout.get(10, TimeUnit.SECONDS);
            String errorOutput = stderr.get(10, TimeUnit.SECONDS);
            Map<String, Object> result = parseNmapResult(xml, errorOutput, exitCode);
            if (exitCode == 0) {
                update(jobId, job -> job.markCompleted(writeJson(result)));
            } else {
                update(jobId, job -> job.markFailed("Nmap termino con codigo " + exitCode, writeJson(result)));
            }
        } catch (Exception ex) {
            Map<String, Object> result = Map.of("error", sample(ex.getMessage(), 1000));
            update(jobId, job -> job.markFailed(sample(ex.getMessage(), 1000), writeJson(result)));
        }
    }

    private void runOpenVas(UUID jobId, OpenVasScanRequest request, String target, RuntimeLog log) {
        update(jobId, job -> job.markRunning("Preparando tarea GVM"));
        try {
            String configId = gvmEntityId("<get_configs/>", "config", valueOrDefault(request.profile(), "Full and fast"));
            String portListId = gvmEntityId("<get_port_lists/>", "port_list", valueOrDefault(request.portList(), "All IANA assigned TCP"));
            String scannerId = gvmEntityId("<get_scanners/>", "scanner", valueOrDefault(request.scanner(), "OpenVAS Default"));
            String aliveTest = valueOrDefault(request.aliveTest(), "Scan Config Default");

            update(jobId, job -> job.updateProgress(8, "Creando target"));
            String targetName = "caligo-" + jobId + "-target";
            String createTargetXml = "<create_target>"
                    + "<name>" + escapeXml(targetName) + "</name>"
                    + "<hosts>" + escapeXml(target) + "</hosts>"
                    + "<alive_tests>" + escapeXml(aliveTest) + "</alive_tests>"
                    + "<port_list id=\"" + escapeXml(portListId) + "\"/>"
                    + "</create_target>";
            String targetXml = runGvmXml(createTargetXml, 60);
            String targetId = responseId(targetXml, "create_target_response");

            update(jobId, job -> job.updateProgress(12, "Creando tarea"));
            String taskName = "caligo-" + jobId;
            String createTaskXml = "<create_task>"
                    + "<name>" + escapeXml(taskName) + "</name>"
                    + "<config id=\"" + escapeXml(configId) + "\"/>"
                    + "<target id=\"" + escapeXml(targetId) + "\"/>"
                    + "<scanner id=\"" + escapeXml(scannerId) + "\"/>"
                    + "</create_task>";
            String taskXml = runGvmXml(createTaskXml, 60);
            String taskId = responseId(taskXml, "create_task_response");

            update(jobId, job -> job.updateProgress(15, "Escaneo iniciado"));
            String startXml = runGvmXml("<start_task task_id=\"" + escapeXml(taskId) + "\"/>", 60);
            String reportId = firstText(parseXml(startXml), "report_id");
            Instant deadline = Instant.now().plusSeconds(openVasTimeoutSeconds);
            TaskState lastState = new TaskState("Requested", 15, reportId);

            while (Instant.now().isBefore(deadline)) {
                Thread.sleep(Math.max(3, openVasPollSeconds) * 1000);
                String taskStatusXml = runGvmXml("<get_tasks task_id=\"" + escapeXml(taskId) + "\" details=\"1\"/>", 90);
                TaskState state = parseTaskState(taskStatusXml, reportId);
                lastState = state;
                reportId = hasText(state.reportId()) ? state.reportId() : reportId;
                log.add(state.status() + " " + state.progress() + "%");
                update(jobId, job -> job.updateProgress(Math.max(15, Math.min(99, state.progress())), "OpenVAS: " + state.status()));
                if ("Done".equalsIgnoreCase(state.status()) || "Stopped".equalsIgnoreCase(state.status()) || "Interrupted".equalsIgnoreCase(state.status())) {
                    break;
                }
            }

            if (!isTerminalOpenVasStatus(lastState.status())) {
                try {
                    runGvmXml("<stop_task task_id=\"" + escapeXml(taskId) + "\"/>", 60);
                } catch (Exception stopException) {
                    log.add("No se pudo detener tarea tras timeout: " + sample(stopException.getMessage(), 240));
                }
                throw new IllegalStateException("Tiempo maximo de OpenVAS superado; tarea detenida si GVM lo permitio");
            }

            update(jobId, job -> job.updateProgress(96, "Recuperando informe"));
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("taskId", taskId);
            result.put("targetId", targetId);
            result.put("reportId", reportId);
            result.put("finalStatus", lastState.status());
            if (hasText(reportId)) {
                String reportXml = runGvmXml("<get_reports report_id=\"" + escapeXml(reportId) + "\" details=\"1\" ignore_pagination=\"1\"/>", 180);
                result.putAll(parseOpenVasReport(reportXml));
            }
            update(jobId, job -> job.markCompleted(writeJson(result)));
        } catch (Exception ex) {
            Map<String, Object> result = Map.of("error", sample(ex.getMessage(), 1000));
            update(jobId, job -> job.markFailed(sample(ex.getMessage(), 1000), writeJson(result)));
        }
    }

    private List<String> buildNmapCommand(NmapScanRequest request, String target) {
        String profile = valueOrDefault(request.profile(), "standard");
        String scanType = valueOrDefault(request.scanType(), "tcp-connect");
        String portMode = valueOrDefault(request.portMode(), "top");
        String timing = valueOrDefault(request.timing(), "T3");

        if (!List.of("quick", "standard", "service", "web", "discovery", "udp-light").contains(profile)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Perfil Nmap no permitido");
        }
        if (!List.of("tcp-connect", "udp").contains(scanType)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Tipo de escaneo no permitido");
        }
        if (!List.of("top", "custom", "all").contains(portMode)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Modo de puertos no permitido");
        }
        if (!List.of("T2", "T3", "T4").contains(timing)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Timing no permitido");
        }

        List<String> command = new ArrayList<>();
        command.add(nmapBinary);
        command.add("-oX");
        command.add("-");
        command.add("--stats-every");
        command.add("5s");
        command.add("--reason");

        if ("discovery".equals(profile)) {
            command.add("-sn");
            command.add("-" + timing);
            command.add(target);
            return command;
        }

        command.add("udp".equals(scanType) || "udp-light".equals(profile) ? "-sU" : "-sT");
        command.add("-" + timing);

        if ("web".equals(profile)) {
            command.add("-p");
            command.add("80,443,8080,8443,8000,3000,5173,5174");
        } else if ("udp-light".equals(profile)) {
            command.add("--top-ports");
            command.add("50");
        } else if ("all".equals(portMode)) {
            command.add("-p-");
        } else if ("custom".equals(portMode)) {
            String ports = valueOrDefault(request.ports(), "");
            if (!SAFE_PORTS.matcher(ports).matches()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Lista de puertos no valida");
            }
            command.add("-p");
            command.add(ports);
        } else {
            command.add("--top-ports");
            command.add(String.valueOf(request.topPorts() == null ? defaultTopPorts(profile) : request.topPorts()));
        }

        if (Boolean.TRUE.equals(request.serviceDetection()) || "standard".equals(profile) || "service".equals(profile) || "web".equals(profile)) {
            command.add("-sV");
        }
        if (Boolean.TRUE.equals(request.defaultScripts()) || "web".equals(profile)) {
            command.add("-sC");
        }
        if (Boolean.TRUE.equals(request.osDetection())) {
            command.add("-O");
        }
        if (Boolean.TRUE.equals(request.traceroute())) {
            command.add("--traceroute");
        }
        if (Boolean.TRUE.equals(request.noPing())) {
            command.add("-Pn");
        }
        if (request.maxRetries() != null) {
            command.add("--max-retries");
            command.add(String.valueOf(request.maxRetries()));
        }

        command.add(target);
        return command;
    }

    private int defaultTopPorts(String profile) {
        return "quick".equals(profile) ? 100 : 1000;
    }

    private String sanitizeTarget(String rawTarget) {
        String target = rawTarget == null ? "" : rawTarget.trim();
        if (target.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "El objetivo es obligatorio");
        }
        if (!SAFE_TARGET.matcher(target).matches() || target.contains("..") || target.contains("//")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Objetivo no valido para ejecucion CLI");
        }
        if (!allowExternalTargets && !isPrivateOrLocalTarget(target)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Solo se permiten objetivos privados/locales salvo configuracion explicita del servidor");
        }
        return target;
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
        if (host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe80:")) {
            return true;
        }
        Matcher matcher = IPV4.matcher(host);
        if (!matcher.matches()) {
            return false;
        }
        int a = parseOctet(matcher.group(1));
        int b = parseOctet(matcher.group(2));
        int c = parseOctet(matcher.group(3));
        int d = parseOctet(matcher.group(4));
        if (a > 255 || b > 255 || c > 255 || d > 255) {
            return false;
        }
        return a == 10
                || a == 127
                || (a == 192 && b == 168)
                || (a == 172 && b >= 16 && b <= 31)
                || (a == 169 && b == 254);
    }

    private int parseOctet(String value) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException ex) {
            return 999;
        }
    }

    private Map<String, Object> parseNmapResult(String xml, String stderr, int exitCode) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("exitCode", exitCode);
        result.put("stderr", sample(stderr, 8000));
        result.put("xmlSample", sample(xml, 12000));
        try {
            Document document = parseXml(xml);
            Element root = document.getDocumentElement();
            result.put("scanner", root.getAttribute("scanner"));
            result.put("version", root.getAttribute("version"));
            result.put("arguments", root.getAttribute("args"));
            result.put("started", root.getAttribute("startstr"));
            List<Map<String, Object>> hosts = new ArrayList<>();
            int open = 0;
            int filtered = 0;
            int closed = 0;
            NodeList hostNodes = document.getElementsByTagName("host");
            for (int i = 0; i < hostNodes.getLength(); i++) {
                Element hostElement = (Element) hostNodes.item(i);
                Map<String, Object> host = new LinkedHashMap<>();
                host.put("status", firstAttr(hostElement, "status", "state"));
                host.put("address", firstAttr(hostElement, "address", "addr"));
                host.put("hostnames", hostnames(hostElement));
                List<Map<String, Object>> ports = ports(hostElement);
                for (Map<String, Object> port : ports) {
                    String state = String.valueOf(port.get("state"));
                    if ("open".equals(state)) {
                        open++;
                    } else if ("filtered".equals(state)) {
                        filtered++;
                    } else if ("closed".equals(state)) {
                        closed++;
                    }
                }
                host.put("ports", ports);
                hosts.add(host);
            }
            result.put("hosts", hosts);
            result.put("summary", Map.of(
                    "hosts", hosts.size(),
                    "openPorts", open,
                    "filteredPorts", filtered,
                    "closedPorts", closed
            ));
        } catch (Exception ex) {
            result.put("parseError", sample(ex.getMessage(), 500));
        }
        return result;
    }

    private List<String> hostnames(Element hostElement) {
        List<String> values = new ArrayList<>();
        NodeList nodes = hostElement.getElementsByTagName("hostname");
        for (int i = 0; i < nodes.getLength(); i++) {
            Element item = (Element) nodes.item(i);
            if (hasText(item.getAttribute("name"))) {
                values.add(item.getAttribute("name"));
            }
        }
        return values;
    }

    private List<Map<String, Object>> ports(Element hostElement) {
        List<Map<String, Object>> values = new ArrayList<>();
        NodeList nodes = hostElement.getElementsByTagName("port");
        for (int i = 0; i < nodes.getLength(); i++) {
            Element portElement = (Element) nodes.item(i);
            Map<String, Object> port = new LinkedHashMap<>();
            port.put("protocol", portElement.getAttribute("protocol"));
            port.put("port", portElement.getAttribute("portid"));
            port.put("state", firstAttr(portElement, "state", "state"));
            port.put("reason", firstAttr(portElement, "state", "reason"));
            Element service = first(portElement, "service");
            if (service != null) {
                port.put("service", service.getAttribute("name"));
                port.put("product", service.getAttribute("product"));
                port.put("version", service.getAttribute("version"));
                port.put("extraInfo", service.getAttribute("extrainfo"));
            }
            values.add(port);
        }
        return values;
    }

    private String runGvmXml(String xml, int timeoutSeconds) throws Exception {
        List<String> command = List.of(
                gvmCliBinary,
                "--timeout", String.valueOf(timeoutSeconds),
                "--gmp-username", gvmUsername,
                "--gmp-password", gvmPassword,
                "socket",
                "--socketpath", gvmSocket,
                "--xml", xml
        );
        Process process = new ProcessBuilder(command).start();
        Future<String> stdout = executor.submit(readStream(process.getInputStream(), line -> {
        }));
        Future<String> stderr = executor.submit(readStream(process.getErrorStream(), line -> {
        }));
        boolean finished = process.waitFor(timeoutSeconds + 5L, TimeUnit.SECONDS);
        if (!finished) {
            process.destroyForcibly();
            throw new IllegalStateException("GVM CLI no respondio a tiempo");
        }
        String out = stdout.get(5, TimeUnit.SECONDS);
        String err = stderr.get(5, TimeUnit.SECONDS);
        if (process.exitValue() != 0) {
            throw new IllegalStateException("GVM CLI fallo: " + sample(err, 1000));
        }
        return out;
    }

    private List<Map<String, String>> gvmEntities(String xml, String tag) throws Exception {
        Document document = parseXml(runGvmXml(xml, 60));
        return entityList(document, tag);
    }

    private String gvmEntityId(String xml, String tag, String desiredName) throws Exception {
        Document document = parseXml(runGvmXml(xml, 60));
        List<Map<String, String>> entities = entityList(document, tag);
        Optional<Map<String, String>> exact = entities.stream()
                .filter(item -> matchesGvmEntity(item, desiredName))
                .findFirst();
        if (exact.isPresent()) {
            return exact.get().get("id");
        }
        return entities.stream()
                .findFirst()
                .map(item -> item.get("id"))
                .orElseThrow(() -> new IllegalStateException("No hay entidades GVM de tipo " + tag));
    }

    private boolean matchesGvmEntity(Map<String, String> item, String desiredName) {
        if (!hasText(desiredName)) {
            return false;
        }
        String desired = desiredName.trim();
        return desired.equalsIgnoreCase(item.getOrDefault("id", ""))
                || desired.equalsIgnoreCase(item.getOrDefault("name", ""))
                || desired.equalsIgnoreCase(item.getOrDefault("label", ""))
                || desired.equalsIgnoreCase(item.getOrDefault("value", ""));
    }

    private List<Map<String, String>> entityList(Document document, String tag) {
        List<Map<String, String>> values = new ArrayList<>();
        NodeList nodes = document.getElementsByTagName(tag);
        for (int i = 0; i < nodes.getLength(); i++) {
            Element item = (Element) nodes.item(i);
            Map<String, String> map = new LinkedHashMap<>();
            map.put("id", item.getAttribute("id"));
            map.put("name", firstText(item, "name"));
            map.put("label", hasText(firstText(item, "name")) ? firstText(item, "name") : item.getAttribute("id"));
            map.put("description", "");
            if (hasText(map.get("id"))) {
                values.add(map);
            }
        }
        return values;
    }

    private String responseId(String xml, String tag) throws Exception {
        Element element = first(parseXml(xml), tag);
        if (element == null || !hasText(element.getAttribute("id"))) {
            throw new IllegalStateException("Respuesta GVM sin id para " + tag);
        }
        return element.getAttribute("id");
    }

    private TaskState parseTaskState(String xml, String fallbackReportId) throws Exception {
        Document document = parseXml(xml);
        Element task = first(document, "task");
        String status = task == null ? "Unknown" : firstText(task, "status");
        int progress = parsePercent(task == null ? "" : firstText(task, "progress"));
        String reportId = fallbackReportId;
        NodeList reports = document.getElementsByTagName("report");
        for (int i = 0; i < reports.getLength(); i++) {
            Element report = (Element) reports.item(i);
            if (hasText(report.getAttribute("id"))) {
                reportId = report.getAttribute("id");
                break;
            }
        }
        return new TaskState(status, progress, reportId);
    }

    private Map<String, Object> parseOpenVasReport(String xml) {
        Map<String, Object> response = new LinkedHashMap<>();
        List<Map<String, Object>> findings = new ArrayList<>();
        try {
            Document document = parseXml(xml);
            NodeList results = document.getElementsByTagName("result");
            for (int i = 0; i < Math.min(results.getLength(), 200); i++) {
                Element result = (Element) results.item(i);
                Map<String, Object> finding = new LinkedHashMap<>();
                finding.put("id", result.getAttribute("id"));
                finding.put("name", firstText(result, "name"));
                finding.put("host", firstText(result, "host"));
                finding.put("port", firstText(result, "port"));
                finding.put("severity", firstText(result, "severity"));
                finding.put("threat", firstText(result, "threat"));
                finding.put("qod", firstText(result, "value"));
                Element nvt = first(result, "nvt");
                if (nvt != null) {
                    finding.put("oid", nvt.getAttribute("oid"));
                    finding.put("family", firstText(nvt, "family"));
                    finding.put("cvssBase", firstText(nvt, "cvss_base"));
                    finding.put("cves", childTexts(nvt, "cve", 12));
                    finding.put("tags", sample(firstText(nvt, "tags"), 1000));
                }
                finding.put("description", sample(firstText(result, "description"), 1000));
                findings.add(finding);
            }
            response.put("findings", findings);
            response.put("findingCount", findings.size());
            response.put("summary", openVasSummary(findings));
        } catch (Exception ex) {
            response.put("parseError", sample(ex.getMessage(), 500));
            response.put("xmlSample", sample(xml, 12000));
        }
        return response;
    }

    private Callable<String> readStream(InputStream stream, java.util.function.Consumer<String> lineConsumer) {
        return () -> {
            StringBuilder output = new StringBuilder();
            int total = 0;
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    lineConsumer.accept(line);
                    byte[] bytes = line.getBytes(StandardCharsets.UTF_8);
                    if (total < maxOutputBytes) {
                        output.append(line).append('\n');
                        total += bytes.length + 1;
                    }
                }
            }
            return output.toString();
        };
    }

    private void update(UUID jobId, java.util.function.Consumer<ToolExecutionJob> mutation) {
        jobs.findById(jobId).ifPresent(job -> {
            mutation.accept(job);
            jobs.save(job);
        });
    }

    private Document parseXml(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        return factory.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }

    private Element first(Document document, String tag) {
        if (document == null) {
            return null;
        }
        Element root = document.getDocumentElement();
        if (root != null && tag.equals(root.getTagName())) {
            return root;
        }
        return first(root, tag);
    }

    private Element first(Element element, String tag) {
        if (element == null) {
            return null;
        }
        if (tag.equals(element.getTagName())) {
            return element;
        }
        NodeList nodes = element.getElementsByTagName(tag);
        return nodes.getLength() == 0 ? null : (Element) nodes.item(0);
    }

    private List<String> childTexts(Element element, String tag, int limit) {
        if (element == null) {
            return List.of();
        }
        List<String> values = new ArrayList<>();
        NodeList nodes = element.getElementsByTagName(tag);
        for (int i = 0; i < nodes.getLength() && values.size() < limit; i++) {
            String value = text((Element) nodes.item(i));
            if (hasText(value) && !values.contains(value)) {
                values.add(value);
            }
        }
        return values;
    }

    private String firstText(Document document, String tag) {
        return text(first(document, tag));
    }

    private String firstText(Element element, String tag) {
        return text(first(element, tag));
    }

    private String firstAttr(Element element, String tag, String attr) {
        Element child = first(element, tag);
        return child == null ? "" : child.getAttribute(attr);
    }

    private String text(Element element) {
        if (element == null) {
            return "";
        }
        Node firstChild = element.getFirstChild();
        return firstChild == null ? "" : firstChild.getTextContent();
    }

    private int parsePercent(String value) {
        try {
            return Math.max(0, Math.min(100, Integer.parseInt(value.trim())));
        } catch (Exception ex) {
            return 0;
        }
    }

    private boolean commandAvailable(String command) {
        if (!hasText(command)) {
            return false;
        }
        Path direct = Path.of(command);
        if (direct.isAbsolute() || command.contains("/") || command.contains("\\")) {
            return Files.isExecutable(direct);
        }
        String path = System.getenv("PATH");
        if (!hasText(path)) {
            return false;
        }
        String[] extensions = System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win")
                ? new String[]{"", ".exe", ".bat", ".cmd"}
                : new String[]{""};
        for (String dir : path.split(Pattern.quote(System.getProperty("path.separator")))) {
            for (String extension : extensions) {
                if (Files.isExecutable(Path.of(dir, command + extension))) {
                    return true;
                }
            }
        }
        return false;
    }

    private Map<String, Object> scopePolicy() {
        return Map.of(
                "allowExternalTargets", allowExternalTargets,
                "defaultPolicy", allowExternalTargets ? "externos-permitidos-por-configuracion" : "solo-privados-locales",
                "examples", List.of("192.168.0.1", "192.168.0.0/24", "10.0.0.5", "host.local")
        );
    }

    private Map<String, String> option(String value, String label, String description) {
        Map<String, String> item = new LinkedHashMap<>();
        item.put("value", value);
        item.put("name", value);
        item.put("label", label);
        item.put("description", description);
        return item;
    }

    private Map<String, Object> openVasDefaults(
            List<Map<String, String>> profiles,
            List<Map<String, String>> portLists,
            List<Map<String, String>> scanners
    ) {
        Map<String, Object> defaults = new LinkedHashMap<>();
        defaults.put("target", "192.168.0.50");
        defaults.put("profile", preferredEntityValue(profiles, "Full and fast"));
        defaults.put("portList", preferredEntityValue(portLists, "All IANA assigned TCP"));
        defaults.put("scanner", preferredEntityValue(scanners, "OpenVAS Default"));
        defaults.put("aliveTest", "Scan Config Default");
        return defaults;
    }

    private String preferredEntityValue(List<Map<String, String>> entities, String preferredName) {
        return entities.stream()
                .filter(item -> matchesGvmEntity(item, preferredName))
                .findFirst()
                .or(() -> entities.stream().findFirst())
                .map(item -> item.getOrDefault("name", item.getOrDefault("id", preferredName)))
                .orElse(preferredName);
    }

    private List<Map<String, String>> usableOpenVasScanners(List<Map<String, String>> scanners) {
        List<Map<String, String>> usable = scanners.stream()
                .filter(item -> item.getOrDefault("name", "").toLowerCase(Locale.ROOT).contains("openvas"))
                .toList();
        return usable.isEmpty() ? scanners : usable;
    }

    private List<Map<String, String>> fallbackOpenVasProfiles() {
        return List.of(
                option("Full and fast", "Full and fast", "Perfil equilibrado de Greenbone."),
                option("Full and very deep", "Full and very deep", "Mas profundo, mas lento."),
                option("Discovery", "Discovery", "Descubrimiento sin pruebas invasivas."),
                option("Host Discovery", "Host Discovery", "Verificacion de hosts vivos.")
        );
    }

    private List<Map<String, String>> fallbackOpenVasPortLists() {
        return List.of(
                option("All IANA assigned TCP", "All IANA TCP", "Puertos TCP asignados por IANA."),
                option("All TCP", "All TCP", "Rango TCP completo."),
                option("All IANA assigned TCP and UDP", "All IANA TCP/UDP", "TCP y UDP asignados por IANA."),
                option("All TCP and Nmap top 100 UDP", "All TCP + top UDP", "Completo TCP y UDP frecuente.")
        );
    }

    private List<Map<String, String>> fallbackOpenVasScanners() {
        return List.of(
                option("OpenVAS Default", "OpenVAS Default", "Scanner local por defecto."),
                option("CVE", "CVE", "Scanner de CVE si esta configurado en GVM.")
        );
    }

    private boolean isTerminalOpenVasStatus(String status) {
        return "Done".equalsIgnoreCase(status) || "Stopped".equalsIgnoreCase(status) || "Interrupted".equalsIgnoreCase(status);
    }

    private Map<String, Object> openVasSummary(List<Map<String, Object>> findings) {
        int critical = 0;
        int high = 0;
        int medium = 0;
        int low = 0;
        int info = 0;
        double maxSeverity = 0;
        for (Map<String, Object> finding : findings) {
            double severity = parseDouble(String.valueOf(finding.getOrDefault("severity", "0")));
            maxSeverity = Math.max(maxSeverity, severity);
            if (severity >= 9) {
                critical++;
            } else if (severity >= 7) {
                high++;
            } else if (severity >= 4) {
                medium++;
            } else if (severity > 0) {
                low++;
            } else {
                info++;
            }
        }
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("total", findings.size());
        summary.put("critical", critical);
        summary.put("high", high);
        summary.put("medium", medium);
        summary.put("low", low);
        summary.put("info", info);
        summary.put("maxSeverity", Math.round(maxSeverity * 10.0) / 10.0);
        return summary;
    }

    private double parseDouble(String value) {
        try {
            return Double.parseDouble(value);
        } catch (Exception ex) {
            return 0;
        }
    }

    private Map<String, Object> readJson(String json) {
        if (!hasText(json)) {
            return null;
        }
        try {
            return objectMapper.readValue(json, new TypeReference<>() {
            });
        } catch (JsonProcessingException ex) {
            return Map.of("raw", json);
        }
    }

    private String writeJson(Object payload) {
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (JsonProcessingException ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "No se pudo serializar el resultado");
        }
    }

    private String preview(List<String> command) {
        return String.join(" ", command.stream().map(this::quotePreview).toList());
    }

    private String quotePreview(String value) {
        if (value.matches("^[A-Za-z0-9_./:-]+$")) {
            return value;
        }
        return "'" + value.replace("'", "'\\''") + "'";
    }

    private String valueOrDefault(String value, String fallback) {
        return hasText(value) ? value.trim() : fallback;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private String string(Instant instant) {
        return instant == null ? null : instant.toString();
    }

    private Long durationMs(Instant startedAt, Instant completedAt) {
        if (startedAt == null) {
            return null;
        }
        Instant end = completedAt == null ? Instant.now() : completedAt;
        return Duration.between(startedAt, end).toMillis();
    }

    private String sample(String value, int maxLength) {
        if (value == null) {
            return "";
        }
        return value.length() <= maxLength ? value : value.substring(0, maxLength);
    }

    private String escapeXml(String value) {
        return value == null ? "" : value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&apos;");
    }

    private record TaskState(String status, int progress, String reportId) {
    }

    private static class RuntimeLog {
        private final List<String> lines = Collections.synchronizedList(new ArrayList<>());

        void add(String line) {
            if (line == null || line.isBlank()) {
                return;
            }
            lines.add(line);
            while (lines.size() > 80) {
                lines.removeFirst();
            }
        }

        List<String> snapshot() {
            synchronized (lines) {
                return List.copyOf(lines);
            }
        }
    }
}
