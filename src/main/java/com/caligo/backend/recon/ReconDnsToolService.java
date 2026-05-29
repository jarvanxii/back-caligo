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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
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
public class ReconDnsToolService {

    private static final Set<String> SUPPORTED_TOOLS = Set.of("assetfinder", "dnsenum", "dnsrecon", "fierce", "fping");
    private static final Pattern SAFE_DOMAIN = Pattern.compile("(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,30}$");
    private static final Pattern SAFE_HOST = Pattern.compile("(?i)^(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,30}|localhost|(?:\\d{1,3}\\.){3}\\d{1,3})(?:/\\d{1,2})?$");
    private static final Pattern SAFE_NAMESERVER = Pattern.compile("(?i)^(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,30}|(?:\\d{1,3}\\.){3}\\d{1,3})$");
    private static final Pattern SAFE_LABEL = Pattern.compile("(?i)^[a-z0-9][a-z0-9-]{0,61}$");
    private static final Pattern HOST_PATTERN = Pattern.compile("(?i)\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,30}\\b");
    private static final Pattern IPV4_PATTERN = Pattern.compile("\\b(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\b");
    private static final List<String> SMALL_DNS_WORDLIST = List.of("www", "mail", "mx", "smtp", "imap", "ns1", "ns2", "vpn", "dev", "stage", "test", "api", "admin", "portal", "intranet");
    private static final List<String> EXTENDED_DNS_WORDLIST = List.of(
            "www", "mail", "mx", "smtp", "imap", "pop", "ns1", "ns2", "ns3", "vpn", "dev", "stage", "staging", "test",
            "api", "admin", "portal", "intranet", "git", "jira", "confluence", "grafana", "kibana", "jenkins", "ci",
            "cdn", "static", "assets", "m", "mobile", "app", "apps", "auth", "sso", "login", "beta", "pre", "prod"
    );

    private final ToolExecutionJobRepository jobs;
    private final AuditEventRepository auditEvents;
    private final ObjectMapper objectMapper;
    private final ExecutorService executor;
    private final Map<UUID, RuntimeLog> runtimeLogs = new ConcurrentHashMap<>();
    private final Map<UUID, Object> jobLocks = new ConcurrentHashMap<>();

    private final String assetfinderBinary;
    private final String dnsenumBinary;
    private final String dnsreconBinary;
    private final String fierceBinary;
    private final String fpingBinary;
    private final boolean allowExternalTargets;
    private final int maxOutputBytes;
    private final long defaultTimeoutSeconds;

    public ReconDnsToolService(
            ToolExecutionJobRepository jobs,
            AuditEventRepository auditEvents,
            ObjectMapper objectMapper,
            @Value("${caligo.recon.assetfinder.binary:/usr/local/bin/assetfinder}") String assetfinderBinary,
            @Value("${caligo.recon.dnsenum.binary:dnsenum}") String dnsenumBinary,
            @Value("${caligo.recon.dnsrecon.binary:/usr/local/bin/dnsrecon}") String dnsreconBinary,
            @Value("${caligo.recon.fierce.binary:fierce}") String fierceBinary,
            @Value("${caligo.recon.fping.binary:fping}") String fpingBinary,
            @Value("${caligo.recon.allow-external-targets:false}") boolean allowExternalTargets,
            @Value("${caligo.recon.max-output-bytes:1048576}") int maxOutputBytes,
            @Value("${caligo.recon.dns-timeout-seconds:600}") long defaultTimeoutSeconds
    ) {
        this.jobs = jobs;
        this.auditEvents = auditEvents;
        this.objectMapper = objectMapper;
        this.assetfinderBinary = assetfinderBinary;
        this.dnsenumBinary = dnsenumBinary;
        this.dnsreconBinary = dnsreconBinary;
        this.fierceBinary = fierceBinary;
        this.fpingBinary = fpingBinary;
        this.allowExternalTargets = allowExternalTargets;
        this.maxOutputBytes = maxOutputBytes;
        this.defaultTimeoutSeconds = Math.max(30, defaultTimeoutSeconds);
        this.executor = Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "caligo-recon-dns-worker");
            thread.setDaemon(true);
            return thread;
        });
    }

    @PreDestroy
    void shutdown() {
        executor.shutdownNow();
    }

    public Map<String, Object> capabilities(String tool) {
        String normalizedTool = sanitizeTool(tool);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("tool", normalizedTool);
        response.put("available", commandAvailable(binary(normalizedTool)));
        response.put("binary", binary(normalizedTool));
        response.put("version", probeVersion(normalizedTool));
        response.put("scope", scopePolicy(normalizedTool));
        response.put("defaults", defaults(normalizedTool));
        response.put("modes", modes(normalizedTool));
        response.put("wordlists", List.of(
                option("small", "Compacta", "15 entradas comunes para pruebas rápidas."),
                option("extended", "Extendida", "40 entradas habituales para una pasada controlada."),
                option("custom", "Personalizada", "Usa los subdominios escritos en la vista.")
        ));
        return response;
    }

    public Map<String, Object> start(String tool, ReconCliScanRequest request, String username, String remoteIp) {
        String normalizedTool = sanitizeTool(tool);
        requireCommand(normalizedTool);
        requireAuthorized(request.authorized());
        CommandSpec spec = commandSpec(normalizedTool, request);
        ToolExecutionJob job = jobs.save(new ToolExecutionJob(
                username,
                normalizedTool,
                spec.target(),
                writeJson(parameters(normalizedTool, request)),
                preview(spec.command())
        ));
        RuntimeLog log = new RuntimeLog();
        runtimeLogs.put(job.getId(), log);
        auditEvents.save(new AuditEvent(username, "RECON_" + normalizedTool.toUpperCase(Locale.ROOT).replace("-", "_") + "_START", spec.target(), remoteIp));
        CompletableFuture.runAsync(() -> runProcessJob(job.getId(), spec, log), executor);
        return job(job.getId(), username, normalizedTool);
    }

    public Map<String, Object> job(UUID id, String username, String expectedTool) {
        String normalizedTool = sanitizeTool(expectedTool);
        ToolExecutionJob job = jobs.findById(id)
                .filter(item -> username.equals(item.getUsername()))
                .filter(item -> normalizedTool.equals(item.getTool()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Job no encontrado"));
        return jobResponse(job);
    }

    public List<Map<String, Object>> recentJobs(String tool, String username) {
        String normalizedTool = sanitizeTool(tool);
        return jobs.findByUsernameAndToolOrderByCreatedAtDesc(username, normalizedTool, PageRequest.of(0, 20)).stream()
                .map(this::jobSummary)
                .toList();
    }

    private void runProcessJob(UUID jobId, CommandSpec spec, RuntimeLog log) {
        update(jobId, job -> job.markRunning("Preparando " + job.getTool()));
        Instant started = Instant.now();
        try {
            update(jobId, job -> job.updateProgress(10, "Lanzando proceso"));
            Process process = new ProcessBuilder(spec.command()).redirectErrorStream(false).start();
            update(jobId, job -> job.updateProgress(28, "Reconocimiento en curso"));
            Future<String> stdout = executor.submit(readStream(process.getInputStream(), line -> {
                log.add(line);
                update(jobId, job -> job.updateProgress(Math.min(88, Math.max(job.getProgress(), job.getProgress() + 1)), "Recolectando salida"));
            }));
            Future<String> stderr = executor.submit(readStream(process.getErrorStream(), log::add));
            boolean finished = process.waitFor(spec.timeoutSeconds(), TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                throw new IllegalStateException("Tiempo máximo de ejecución superado");
            }
            update(jobId, job -> job.updateProgress(90, "Normalizando resultados"));
            String out = stdout.get(5, TimeUnit.SECONDS);
            String err = stderr.get(5, TimeUnit.SECONDS);
            int exitCode = process.exitValue();
            Map<String, Object> result = spec.parser().parse(out, err, exitCode);
            result.put("durationMs", Duration.between(started, Instant.now()).toMillis());
            if (!spec.acceptedExitCodes().contains(exitCode) && hasUsefulOutput(result)) {
                result.put("exitWarning", "La herramienta terminó con código " + exitCode + ", pero se conservaron resultados útiles.");
            }
            if (spec.acceptedExitCodes().contains(exitCode) || hasUsefulOutput(result)) {
                update(jobId, job -> job.markCompleted(writeJson(result)));
            } else {
                update(jobId, job -> job.markFailed("La herramienta terminó con código " + exitCode, writeJson(result)));
            }
        } catch (Exception ex) {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("error", sample(ex.getMessage(), 900));
            result.put("logs", log.snapshot());
            update(jobId, job -> job.markFailed(sample(ex.getMessage(), 900), writeJson(result)));
        } finally {
            for (Path tempFile : spec.tempFiles()) {
                try {
                    Files.deleteIfExists(tempFile);
                } catch (IOException ignored) {
                    // Limpieza best-effort de temporales.
                }
            }
            jobLocks.remove(jobId);
        }
    }

    private CommandSpec commandSpec(String tool, ReconCliScanRequest request) {
        return switch (tool) {
            case "assetfinder" -> assetfinderCommand(request);
            case "dnsenum" -> dnsenumCommand(request);
            case "dnsrecon" -> dnsreconCommand(request);
            case "fierce" -> fierceCommand(request);
            case "fping" -> fpingCommand(request);
            default -> throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Herramienta no registrada");
        };
    }

    private CommandSpec assetfinderCommand(ReconCliScanRequest request) {
        String domain = sanitizeDomain(request.target());
        List<String> command = new ArrayList<>();
        command.add(assetfinderBinary);
        if (Boolean.TRUE.equals(request.subsOnly())) {
            command.add("-subs-only");
        }
        command.add(domain);
        return new CommandSpec(command, domain, timeout(request, 240), List.of(), Set.of(0), (stdout, stderr, exitCode) -> parseLines("assetfinder", stdout, stderr, exitCode));
    }

    private CommandSpec dnsenumCommand(ReconCliScanRequest request) {
        String domain = sanitizeDomain(request.target());
        List<Path> tempFiles = new ArrayList<>();
        List<String> command = new ArrayList<>();
        command.add(dnsenumBinary);
        command.add("--nocolor");
        command.add("-t");
        command.add(String.valueOf(clamp(value(request.timeoutSeconds(), 10), 3, 30)));
        command.add("--threads");
        command.add(String.valueOf(clamp(value(request.threads(), 5), 1, 40)));
        if (hasText(request.nameServer())) {
            command.add("--dnsserver");
            command.add(sanitizeNameServer(request.nameServer()));
        }
        String mode = valueOrDefault(request.mode(), "standard");
        if ("enum".equals(mode)) {
            command.add("--enum");
        }
        if (Boolean.FALSE.equals(request.reverseLookup())) {
            command.add("--noreverse");
        }
        if (Boolean.TRUE.equals(request.bruteForce()) || "bruteforce".equals(mode)) {
            Path wordlist = temporaryWordlist(request);
            tempFiles.add(wordlist);
            command.add("-f");
            command.add(wordlist.toString());
        }
        command.add(domain);
        return new CommandSpec(command, domain, timeout(request, 600), tempFiles, Set.of(0), (stdout, stderr, exitCode) -> parseLines("dnsenum", stdout, stderr, exitCode));
    }

    private CommandSpec dnsreconCommand(ReconCliScanRequest request) {
        String domain = sanitizeDomain(request.target());
        List<Path> tempFiles = new ArrayList<>();
        List<String> command = new ArrayList<>();
        Path jsonFile;
        try {
            jsonFile = Files.createTempFile("caligo-dnsrecon-", ".json");
        } catch (IOException ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "No se pudo preparar salida JSON");
        }
        tempFiles.add(jsonFile);
        command.add(dnsreconBinary);
        command.add("-d");
        command.add(domain);
        command.add("--threads");
        command.add(String.valueOf(clamp(value(request.threads(), 10), 1, 80)));
        command.add("--lifetime");
        command.add(String.valueOf(clamp(value(request.timeoutSeconds(), 4), 2, 30)));
        command.add("-t");
        String mode = dnsreconMode(request.mode());
        command.add(mode);
        if (hasText(request.nameServer())) {
            command.add("-n");
            command.add(sanitizeNameServer(request.nameServer()));
        }
        if ("brt".equals(mode) || "snoop".equals(mode)) {
            Path wordlist = temporaryWordlist(request);
            tempFiles.add(wordlist);
            command.add("-D");
            command.add(wordlist.toString());
            command.add("-f");
        }
        if ("std".equals(mode)) {
            if (Boolean.TRUE.equals(request.zoneTransfer())) command.add("-a");
            if (Boolean.TRUE.equals(request.reverseLookup())) command.add("-s");
            if (Boolean.TRUE.equals(request.bing())) command.add("-b");
            if (Boolean.TRUE.equals(request.yandex())) command.add("-y");
            if (Boolean.TRUE.equals(request.crtsh())) command.add("-k");
            if (Boolean.TRUE.equals(request.whois())) command.add("-w");
            if (Boolean.TRUE.equals(request.dnssec())) command.add("-z");
        }
        if (Boolean.TRUE.equals(request.tcp())) {
            command.add("--tcp");
        }
        command.add("-j");
        command.add(jsonFile.toString());
        return new CommandSpec(command, domain, timeout(request, 600), tempFiles, Set.of(0), (stdout, stderr, exitCode) -> parseDnsRecon(stdout, stderr, exitCode, jsonFile));
    }

    private CommandSpec fierceCommand(ReconCliScanRequest request) {
        String domain = sanitizeDomain(request.target());
        List<String> command = new ArrayList<>();
        command.add(fierceBinary);
        command.add("--domain");
        command.add(domain);
        command.add("--delay");
        command.add(String.valueOf(Math.max(0, value(request.intervalMillis(), 500) / 1000.0)));
        if (Boolean.TRUE.equals(request.wide())) command.add("--wide");
        if (Boolean.TRUE.equals(request.connect())) command.add("--connect");
        if (Boolean.TRUE.equals(request.tcp())) command.add("--tcp");
        if (hasText(request.nameServer())) {
            command.add("--dns-servers");
            command.add(sanitizeNameServer(request.nameServer()));
        }
        List<String> subdomains = sanitizeLabels(request.subdomains(), 40);
        if (!subdomains.isEmpty()) {
            command.add("--subdomains");
            command.addAll(subdomains);
        }
        return new CommandSpec(command, domain, timeout(request, 420), List.of(), Set.of(0), (stdout, stderr, exitCode) -> parseLines("fierce", stdout, stderr, exitCode));
    }

    private CommandSpec fpingCommand(ReconCliScanRequest request) {
        List<String> targets = sanitizeFpingTargets(request.target());
        List<String> command = new ArrayList<>();
        command.add(fpingBinary);
        command.add("-e");
        command.add("-c");
        command.add(String.valueOf(clamp(value(request.count(), 1), 1, 10)));
        command.add("-p");
        command.add(String.valueOf(clamp(value(request.intervalMillis(), 500), 100, 5000)));
        command.add("-t");
        command.add(String.valueOf(clamp(value(request.timeoutMillis(), 1000), 100, 10000)));
        if (Boolean.TRUE.equals(request.aliveOnly())) {
            command.add("-a");
        }
        if (targets.size() == 1 && isCidr(targets.get(0))) {
            String target = targets.get(0);
            if (!allowExternalTargets && !isPrivateOrLocalTarget(target)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "fping solo admite objetivos privados/locales salvo configuración explícita del servidor");
            }
            command.add("-g");
            command.add(target);
        } else {
            for (String target : targets) {
                if (!allowExternalTargets && !isPrivateOrLocalTarget(target)) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "fping solo admite objetivos privados/locales salvo configuración explícita del servidor");
                }
                command.add(target);
            }
        }
        return new CommandSpec(command, String.join(",", targets), timeout(request, 300), List.of(), Set.of(0, 1), this::parseFping);
    }

    private Map<String, Object> parseDnsRecon(String stdout, String stderr, int exitCode, Path jsonFile) {
        Map<String, Object> response = parseLines("dnsrecon", stdout, stderr, exitCode);
        try {
            if (Files.size(jsonFile) > 0) {
                Object json = objectMapper.readValue(Files.readString(jsonFile), Object.class);
                response.put("json", json);
                response.put("records", json);
                List<Map<String, Object>> structuredFindings = new ArrayList<>(asMapList(json));
                if (!structuredFindings.isEmpty()) {
                    response.put("findings", mergeFindings(structuredFindings, asMapList(response.get("findings"))));
                    response.put("findingCount", asMapList(response.get("findings")).size());
                }
            }
        } catch (Exception ex) {
            response.put("jsonParseError", sample(ex.getMessage(), 400));
        }
        return response;
    }

    private Map<String, Object> parseFping(String stdout, String stderr, int exitCode) {
        String combined = (stdout == null ? "" : stdout) + "\n" + (stderr == null ? "" : stderr);
        List<Map<String, Object>> findings = new ArrayList<>();
        for (String line : combined.split("\\R")) {
            if (!hasText(line)) {
                continue;
            }
            Matcher ipMatcher = IPV4_PATTERN.matcher(line);
            if (ipMatcher.find()) {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("type", "host");
                item.put("address", ipMatcher.group());
                item.put("alive", line.toLowerCase(Locale.ROOT).contains("alive") || line.contains(": [0]"));
                item.put("line", sample(line.trim(), 420));
                findings.add(item);
            }
        }
        Map<String, Object> response = baseResult("fping", stdout, stderr, exitCode, findings);
        long alive = findings.stream().filter(item -> Boolean.TRUE.equals(item.get("alive"))).count();
        response.put("summary", Map.of("hosts", findings.size(), "alive", alive, "unreachable", Math.max(0, findings.size() - alive)));
        return response;
    }

    private Map<String, Object> parseLines(String tool, String stdout, String stderr, int exitCode) {
        String combined = (stdout == null ? "" : stdout) + "\n" + (stderr == null ? "" : stderr);
        List<Map<String, Object>> findings = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (String line : combined.split("\\R")) {
            if (!hasText(line) || findings.size() >= 250) {
                continue;
            }
            Matcher hostMatcher = HOST_PATTERN.matcher(line);
            boolean matched = false;
            while (hostMatcher.find() && findings.size() < 250) {
                String host = hostMatcher.group().toLowerCase(Locale.ROOT);
                if (seen.add("host:" + host)) {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("type", "host");
                    item.put("host", host);
                    item.put("line", sample(line.trim(), 420));
                    findings.add(item);
                }
                matched = true;
            }
            Matcher ipMatcher = IPV4_PATTERN.matcher(line);
            while (ipMatcher.find() && findings.size() < 250) {
                String address = ipMatcher.group();
                if (seen.add("ip:" + address)) {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("type", "ip");
                    item.put("address", address);
                    item.put("line", sample(line.trim(), 420));
                    findings.add(item);
                }
                matched = true;
            }
            if (!matched && line.toLowerCase(Locale.ROOT).contains("found") && findings.size() < 250) {
                String value = sample(line.trim(), 420);
                if (seen.add("line:" + value)) {
                    findings.add(Map.of("type", "signal", "line", value));
                }
            }
        }
        return baseResult(tool, stdout, stderr, exitCode, findings);
    }

    private Map<String, Object> baseResult(String tool, String stdout, String stderr, int exitCode, List<Map<String, Object>> findings) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("tool", tool);
        response.put("exitCode", exitCode);
        response.put("stdout", sample(stdout, 16000));
        response.put("stderr", sample(stderr, 8000));
        response.put("findings", findings);
        response.put("findingCount", findings.size());
        response.put("summary", Map.of(
                "findings", findings.size(),
                "hosts", findings.stream().filter(item -> item.containsKey("host")).count(),
                "addresses", findings.stream().filter(item -> item.containsKey("address")).count()
        ));
        return response;
    }

    private Map<String, Object> jobResponse(ToolExecutionJob job) {
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

    private Map<String, Object> jobSummary(ToolExecutionJob job) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("id", job.getId());
        row.put("tool", job.getTool());
        row.put("target", job.getTarget());
        row.put("status", job.getStatus());
        row.put("progress", job.getProgress());
        row.put("phase", job.getPhase());
        row.put("createdAt", string(job.getCreatedAt()));
        row.put("completedAt", string(job.getCompletedAt()));
        row.put("parameters", readJson(job.getParametersJson()));
        row.put("result", readJson(job.getResultJson()));
        return row;
    }

    private Map<String, Object> parameters(String tool, ReconCliScanRequest request) {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("tool", tool);
        params.put("mode", valueOrDefault(request.mode(), defaultMode(tool)));
        params.put("wordlist", valueOrDefault(request.wordlist(), "small"));
        params.put("nameServer", text(request.nameServer()));
        params.put("subsOnly", Boolean.TRUE.equals(request.subsOnly()));
        params.put("bruteForce", Boolean.TRUE.equals(request.bruteForce()));
        params.put("zoneTransfer", Boolean.TRUE.equals(request.zoneTransfer()));
        params.put("reverseLookup", Boolean.TRUE.equals(request.reverseLookup()));
        params.put("crtsh", Boolean.TRUE.equals(request.crtsh()));
        params.put("bing", Boolean.TRUE.equals(request.bing()));
        params.put("yandex", Boolean.TRUE.equals(request.yandex()));
        params.put("whois", Boolean.TRUE.equals(request.whois()));
        params.put("dnssec", Boolean.TRUE.equals(request.dnssec()));
        params.put("tcp", Boolean.TRUE.equals(request.tcp()));
        params.put("wide", Boolean.TRUE.equals(request.wide()));
        params.put("connect", Boolean.TRUE.equals(request.connect()));
        params.put("aliveOnly", Boolean.TRUE.equals(request.aliveOnly()));
        params.put("threads", value(request.threads(), "fping".equals(tool) ? 1 : 10));
        params.put("count", value(request.count(), 1));
        params.put("intervalMillis", value(request.intervalMillis(), "fierce".equals(tool) ? 500 : 500));
        params.put("timeoutMillis", value(request.timeoutMillis(), 1000));
        params.put("timeoutSeconds", value(request.timeoutSeconds(), (int) defaultTimeoutSeconds));
        params.put("subdomains", sanitizeLabels(request.subdomains(), 80));
        return params;
    }

    private Path temporaryWordlist(ReconCliScanRequest request) {
        List<String> words;
        String wordlist = valueOrDefault(request.wordlist(), "small");
        if ("custom".equals(wordlist)) {
            words = sanitizeLabels(request.subdomains(), 100);
            if (words.isEmpty()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "La wordlist personalizada necesita subdominios");
            }
        } else if ("extended".equals(wordlist)) {
            words = EXTENDED_DNS_WORDLIST;
        } else {
            words = SMALL_DNS_WORDLIST;
        }
        try {
            Path file = Files.createTempFile("caligo-dns-wordlist-", ".txt");
            Files.write(file, words, StandardCharsets.UTF_8);
            return file;
        } catch (IOException ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "No se pudo preparar wordlist temporal");
        }
    }

    private List<String> sanitizeLabels(List<String> values, int max) {
        if (values == null) {
            return List.of();
        }
        List<String> output = new ArrayList<>();
        for (String value : values) {
            String label = text(value).toLowerCase(Locale.ROOT);
            if (!hasText(label)) {
                continue;
            }
            if (!SAFE_LABEL.matcher(label).matches()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Subdominio no válido: " + sample(label, 40));
            }
            if (!output.contains(label)) {
                output.add(label);
            }
            if (output.size() >= max) {
                break;
            }
        }
        return output;
    }

    private List<String> sanitizeFpingTargets(String rawTarget) {
        List<String> values = List.of(rawTarget.split("[,\\s]+")).stream()
                .map(this::text)
                .filter(ReconDnsToolService::hasText)
                .distinct()
                .limit(128)
                .toList();
        if (values.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "El objetivo es obligatorio");
        }
        for (String value : values) {
            if (!SAFE_HOST.matcher(value).matches() || !validIpv4Octets(value)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Objetivo fping no válido: " + sample(value, 80));
            }
        }
        return values;
    }

    private String sanitizeDomain(String rawTarget) {
        String target = text(rawTarget).toLowerCase(Locale.ROOT);
        target = target.replaceFirst("(?i)^https?://", "");
        int slash = target.indexOf('/');
        if (slash >= 0) {
            target = target.substring(0, slash);
        }
        if (!SAFE_DOMAIN.matcher(target).matches()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Dominio no válido");
        }
        return target;
    }

    private String sanitizeNameServer(String rawValue) {
        String value = text(rawValue).toLowerCase(Locale.ROOT);
        if (!SAFE_NAMESERVER.matcher(value).matches() || !validIpv4Octets(value)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Servidor DNS no válido");
        }
        return value;
    }

    private void requireAuthorized(Boolean authorized) {
        if (!Boolean.TRUE.equals(authorized)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Confirma que el objetivo pertenece a un entorno autorizado");
        }
    }

    private void requireCommand(String tool) {
        if (!commandAvailable(binary(tool))) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, label(tool) + " no está instalado o no está en PATH");
        }
    }

    private String sanitizeTool(String tool) {
        String normalized = text(tool).toLowerCase(Locale.ROOT);
        if (!SUPPORTED_TOOLS.contains(normalized)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Herramienta de reconocimiento no registrada");
        }
        return normalized;
    }

    private String binary(String tool) {
        return switch (tool) {
            case "assetfinder" -> assetfinderBinary;
            case "dnsenum" -> dnsenumBinary;
            case "dnsrecon" -> dnsreconBinary;
            case "fierce" -> fierceBinary;
            case "fping" -> fpingBinary;
            default -> tool;
        };
    }

    private String label(String tool) {
        return switch (tool) {
            case "assetfinder" -> "assetfinder";
            case "dnsenum" -> "DNSEnum";
            case "dnsrecon" -> "DNSRecon";
            case "fierce" -> "Fierce";
            case "fping" -> "fping";
            default -> tool;
        };
    }

    private String defaultMode(String tool) {
        return switch (tool) {
            case "dnsenum" -> "standard";
            case "dnsrecon" -> "standard";
            case "fierce" -> "domain";
            case "fping" -> "alive";
            default -> "passive";
        };
    }

    private String dnsreconMode(String mode) {
        return switch (valueOrDefault(mode, "standard")) {
            case "bruteforce" -> "brt";
            case "axfr" -> "axfr";
            case "crtsh" -> "crt";
            case "srv" -> "srv";
            case "reverse" -> "rvl";
            case "zonewalk" -> "zonewalk";
            default -> "std";
        };
    }

    private List<Map<String, String>> modes(String tool) {
        return switch (tool) {
            case "assetfinder" -> List.of(
                    option("passive", "Pasivo", "Fuentes OSINT rápidas para dominios y subdominios relacionados."),
                    option("subs-only", "Solo subdominios", "Filtra el dominio raíz y conserva subdominios.")
            );
            case "dnsenum" -> List.of(
                    option("standard", "Estándar", "Registros DNS comunes con salida legible."),
                    option("bruteforce", "Bruteforce DNS", "Wordlist acotada contra subdominios autorizados."),
                    option("enum", "Enum shortcut", "Modo combinado propio de dnsenum: threads, scraping y whois.")
            );
            case "dnsrecon" -> List.of(
                    option("standard", "Estándar", "SOA, NS, A, AAAA, MX y SRV."),
                    option("bruteforce", "Bruteforce", "Diccionario de subdominios controlado."),
                    option("axfr", "AXFR", "Prueba transferencias de zona en dominios propios."),
                    option("crtsh", "crt.sh", "Consulta certificados públicos para subdominios."),
                    option("srv", "SRV", "Enumera registros SRV."),
                    option("zonewalk", "Zone walk", "Prueba NSEC en DNSSEC cuando aplique.")
            );
            case "fierce" -> List.of(
                    option("domain", "Dominio", "Búsqueda DNS de subdominios y rangos relacionados."),
                    option("wide", "Wide", "Amplía búsqueda sobre rangos cercanos descubiertos.")
            );
            case "fping" -> List.of(
                    option("alive", "Alive sweep", "Detecta hosts vivos con ICMP ligero."),
                    option("stats", "Estadísticas", "Muestra estadísticas de pérdida y latencia.")
            );
            default -> List.of();
        };
    }

    private Map<String, Object> defaults(String tool) {
        Map<String, Object> defaults = new LinkedHashMap<>();
        defaults.put("target", "fping".equals(tool) ? "127.0.0.1" : "iana.org");
        defaults.put("mode", defaultMode(tool));
        defaults.put("wordlist", "small");
        defaults.put("threads", "fping".equals(tool) ? 1 : 10);
        defaults.put("count", 1);
        defaults.put("intervalMillis", 500);
        defaults.put("timeoutMillis", 1000);
        defaults.put("timeoutSeconds", Math.min(defaultTimeoutSeconds, 120));
        defaults.put("authorized", false);
        defaults.put("subsOnly", true);
        defaults.put("reverseLookup", false);
        defaults.put("aliveOnly", true);
        defaults.put("subdomains", SMALL_DNS_WORDLIST.subList(0, 6));
        return defaults;
    }

    private Map<String, Object> scopePolicy(String tool) {
        return Map.of(
                "allowExternalTargets", allowExternalTargets,
                "requiresAuthorization", true,
                "activeNetworkProbe", "fping".equals(tool),
                "defaultPolicy", "fping".equals(tool) && !allowExternalTargets ? "solo-privados-locales" : "dominios-autorizados",
                "examples", "fping".equals(tool) ? List.of("127.0.0.1", "192.168.0.253", "192.168.0.0/30") : List.of("iana.org", "example.org", "dominio-propio.tld")
        );
    }

    private String probeVersion(String tool) {
        List<String> command = switch (tool) {
            case "assetfinder" -> List.of(binary(tool), "--help");
            case "dnsenum" -> List.of(binary(tool), "-h");
            case "dnsrecon" -> List.of(binary(tool), "-V");
            case "fierce" -> List.of(binary(tool), "--help");
            case "fping" -> List.of(binary(tool), "-v");
            default -> List.of(binary(tool), "--version");
        };
        try {
            Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
            Future<String> output = executor.submit(readStream(process.getInputStream(), line -> {
            }));
            process.waitFor(8, TimeUnit.SECONDS);
            return inlineSample(output.get(2, TimeUnit.SECONDS), 160);
        } catch (Exception ex) {
            return "";
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
        for (String dir : path.split(Pattern.quote(System.getProperty("path.separator")))) {
            if (Files.isExecutable(Path.of(dir, command))) {
                return true;
            }
        }
        return false;
    }

    private boolean isPrivateOrLocalTarget(String target) {
        String host = target;
        int slash = host.indexOf('/');
        if (slash >= 0) {
            host = host.substring(0, slash);
        }
        host = host.toLowerCase(Locale.ROOT);
        if ("localhost".equals(host) || host.endsWith(".local")) {
            return true;
        }
        Matcher matcher = IPV4_PATTERN.matcher(host);
        if (!matcher.matches()) {
            return false;
        }
        String[] parts = host.split("\\.");
        int a = Integer.parseInt(parts[0]);
        int b = Integer.parseInt(parts[1]);
        return a == 10
                || a == 127
                || (a == 192 && b == 168)
                || (a == 172 && b >= 16 && b <= 31)
                || (a == 169 && b == 254);
    }

    private boolean validIpv4Octets(String target) {
        String host = target;
        int slash = host.indexOf('/');
        if (slash >= 0) {
            int prefix = parseInt(host.substring(slash + 1), -1);
            if (prefix < 0 || prefix > 32) {
                return false;
            }
            host = host.substring(0, slash);
        }
        Matcher matcher = IPV4_PATTERN.matcher(host);
        if (!matcher.matches()) {
            return true;
        }
        for (String part : host.split("\\.")) {
            int value = parseInt(part, 999);
            if (value > 255) {
                return false;
            }
        }
        return true;
    }

    private boolean isCidr(String target) {
        return target.contains("/") && IPV4_PATTERN.matcher(target.substring(0, target.indexOf('/'))).matches();
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
        Object lock = jobLocks.computeIfAbsent(jobId, ignored -> new Object());
        synchronized (lock) {
            jobs.findById(jobId).ifPresent(job -> {
                mutation.accept(job);
                jobs.save(job);
            });
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

    private long durationMs(Instant started, Instant completed) {
        if (started == null) {
            return 0;
        }
        Instant end = completed == null ? Instant.now() : completed;
        return Math.max(0, Duration.between(started, end).toMillis());
    }

    private String string(Instant instant) {
        return instant == null ? null : instant.toString();
    }

    private int timeout(ReconCliScanRequest request, int fallback) {
        return clamp(value(request.timeoutSeconds(), fallback), 5, (int) defaultTimeoutSeconds);
    }

    private int value(Integer value, int fallback) {
        return value == null ? fallback : value;
    }

    private int parseInt(String value, int fallback) {
        try {
            return Integer.parseInt(value);
        } catch (Exception ex) {
            return fallback;
        }
    }

    private int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }

    private String valueOrDefault(String value, String fallback) {
        String cleaned = text(value);
        return hasText(cleaned) ? cleaned : fallback;
    }

    private String text(String value) {
        return value == null ? "" : value.trim();
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private Map<String, String> option(String value, String label, String description) {
        Map<String, String> item = new LinkedHashMap<>();
        item.put("value", value);
        item.put("name", value);
        item.put("label", label);
        item.put("description", description);
        return item;
    }

    private String preview(List<String> command) {
        return String.join(" ", command);
    }

    private String sample(String value, int maxChars) {
        if (value == null) {
            return "";
        }
        String cleaned = value.replace("\u001B", "");
        if (cleaned.length() <= maxChars) {
            return cleaned;
        }
        return cleaned.substring(0, Math.max(0, maxChars - 18)) + "\n[...truncado...]";
    }

    private String inlineSample(String value, int maxChars) {
        String cleaned = sample(value, maxChars).replaceAll("\\s+", " ").trim();
        return cleaned.length() <= maxChars ? cleaned : cleaned.substring(0, Math.max(0, maxChars - 3)) + "...";
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> asMapList(Object value) {
        if (value instanceof List<?> list) {
            return list.stream()
                    .filter(Map.class::isInstance)
                    .map(item -> (Map<String, Object>) item)
                    .toList();
        }
        if (value instanceof Map<?, ?> map && map.get("records") instanceof List<?> records) {
            return records.stream()
                    .filter(Map.class::isInstance)
                    .map(item -> (Map<String, Object>) item)
                    .toList();
        }
        return List.of();
    }

    private List<Map<String, Object>> mergeFindings(List<Map<String, Object>> first, List<Map<String, Object>> second) {
        List<Map<String, Object>> output = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (Map<String, Object> item : first) {
            String key = String.valueOf(item);
            if (seen.add(key)) {
                output.add(item);
            }
        }
        for (Map<String, Object> item : second) {
            String key = String.valueOf(item);
            if (seen.add(key)) {
                output.add(item);
            }
        }
        return output;
    }

    private boolean hasUsefulOutput(Map<String, Object> result) {
        Object findingCount = result.get("findingCount");
        if (findingCount instanceof Number number && number.intValue() > 0) {
            return true;
        }
        Object findings = result.get("findings");
        return findings instanceof List<?> list && !list.isEmpty();
    }

    private record CommandSpec(
            List<String> command,
            String target,
            long timeoutSeconds,
            List<Path> tempFiles,
            Set<Integer> acceptedExitCodes,
            ResultParser parser
    ) {
    }

    @FunctionalInterface
    private interface ResultParser {
        Map<String, Object> parse(String stdout, String stderr, int exitCode);
    }

    private static class RuntimeLog {
        private static final int MAX_LINES = 220;
        private final List<String> lines = new ArrayList<>();

        synchronized void add(String line) {
            if (!hasText(line)) {
                return;
            }
            if (lines.size() >= MAX_LINES) {
                lines.remove(0);
            }
            lines.add(line.length() <= 500 ? line : line.substring(0, 482) + "\n[...truncado...]");
        }

        synchronized List<String> snapshot() {
            return List.copyOf(lines);
        }
    }
}
