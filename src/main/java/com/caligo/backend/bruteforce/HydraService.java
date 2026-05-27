package com.caligo.backend.bruteforce;

import com.caligo.backend.audit.AuditEvent;
import com.caligo.backend.audit.AuditEventRepository;
import com.caligo.backend.recon.ToolExecutionJob;
import com.caligo.backend.recon.ToolExecutionJobRepository;
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
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

@Service
public class HydraService {

    private static final Pattern SAFE_TARGET = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9_.:-]{0,179}$");
    private static final Pattern IPV4 = Pattern.compile("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");
    private static final Pattern SAFE_SERVICE = Pattern.compile("^[a-z0-9][a-z0-9_-]{1,47}$");
    private static final Pattern FOUND_CREDENTIAL = Pattern.compile(
            "\\[(\\d+)]\\[([^]]+)]\\s+host:\\s+(\\S+)\\s+(?:port:\\s+(\\d+)\\s+)?login:\\s+(.+?)\\s+password:\\s+(.+?)\\s*$",
            Pattern.CASE_INSENSITIVE | Pattern.MULTILINE
    );
    private static final Pattern ATTEMPT = Pattern.compile("\\[ATTEMPT]", Pattern.CASE_INSENSITIVE);
    private static final List<String> SERVICES = List.of(
            "ssh", "ftp", "ftps", "telnet", "smtp", "smtps", "pop3", "pop3s", "imap", "imaps",
            "smb", "smbnt", "rdp", "vnc", "mysql", "postgres", "mssql", "oracle-listener",
            "redis", "mongodb", "ldap2", "ldap3", "http-get", "https-get", "http-head",
            "https-head", "http-post-form", "https-post-form", "http-get-form", "https-get-form"
    );

    private final ToolExecutionJobRepository jobs;
    private final AuditEventRepository auditEvents;
    private final ObjectMapper objectMapper;
    private final ExecutorService executor;
    private final Map<UUID, RuntimeLog> runtimeLogs = new ConcurrentHashMap<>();
    private final String hydraBinary;
    private final boolean allowExternalTargets;
    private final int maxOutputBytes;
    private final long jobTimeoutSeconds;
    private final List<Path> wordlistRoots;

    public HydraService(
            ToolExecutionJobRepository jobs,
            AuditEventRepository auditEvents,
            ObjectMapper objectMapper,
            @Value("${caligo.bruteforce.hydra.binary:hydra}") String hydraBinary,
            @Value("${caligo.bruteforce.allow-external-targets:false}") boolean allowExternalTargets,
            @Value("${caligo.bruteforce.max-output-bytes:1048576}") int maxOutputBytes,
            @Value("${caligo.bruteforce.timeout-seconds:1800}") long jobTimeoutSeconds,
            @Value("${caligo.bruteforce.wordlist-roots:/opt/caligo/wordlists,/usr/share/wordlists}") String wordlistRoots
    ) {
        this.jobs = jobs;
        this.auditEvents = auditEvents;
        this.objectMapper = objectMapper;
        this.hydraBinary = hydraBinary;
        this.allowExternalTargets = allowExternalTargets;
        this.maxOutputBytes = maxOutputBytes;
        this.jobTimeoutSeconds = jobTimeoutSeconds;
        this.wordlistRoots = parseRoots(wordlistRoots);
        this.executor = Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "caligo-hydra-worker");
            thread.setDaemon(true);
            return thread;
        });
    }

    @PreDestroy
    void shutdown() {
        executor.shutdownNow();
    }

    public Map<String, Object> capabilities() {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("tool", "hydra");
        response.put("available", commandAvailable(hydraBinary));
        response.put("binary", hydraBinary);
        response.put("version", hydraVersion());
        response.put("scope", scopePolicy());
        response.put("services", SERVICES.stream()
                .map(service -> option(service, service.toUpperCase(Locale.ROOT), serviceDescription(service)))
                .toList());
        response.put("usernameModes", List.of(
                option("single", "Usuario unico", "Un login concreto."),
                option("list", "Lista pegada", "Varios usuarios escritos en la peticion."),
                option("file", "Wordlist servidor", "Fichero permitido en el servidor.")
        ));
        response.put("passwordModes", List.of(
                option("single", "Password unico", "Una clave concreta."),
                option("list", "Lista pegada", "Varias claves escritas en la peticion."),
                option("file", "Wordlist servidor", "Fichero permitido en el servidor."),
                option("combo", "Combo login:pass", "Fichero colon-separated compatible con -C.")
        ));
        response.put("wordlists", wordlists());
        response.put("wordlistRoots", wordlistRoots.stream().map(Path::toString).toList());
        Map<String, Object> defaults = new LinkedHashMap<>();
        defaults.put("target", "192.168.0.1");
        defaults.put("service", "ssh");
        defaults.put("port", 22);
        defaults.put("usernameMode", "single");
        defaults.put("username", "hacker");
        defaults.put("passwordMode", "single");
        defaults.put("password", "password123");
        defaults.put("tasks", 4);
        defaults.put("connectTimeoutSeconds", 10);
        defaults.put("responseWaitSeconds", 5);
        defaults.put("stopOnFound", true);
        defaults.put("exitOnFirstHost", false);
        defaults.put("loopUsers", false);
        defaults.put("verboseAttempts", false);
        defaults.put("debugVerbose", false);
        defaults.put("httpPath", "/login");
        defaults.put("httpParameters", "username=^USER^&password=^PASS^");
        defaults.put("httpFailCondition", "F=incorrect");
        response.put("defaults", defaults);
        return response;
    }

    public Map<String, Object> start(HydraScanRequest request, String username, String remoteIp) {
        if (!commandAvailable(hydraBinary)) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Hydra no esta instalado o no esta en PATH");
        }
        String target = sanitizeTarget(request.target());
        String service = sanitizeService(request.service());
        HydraCommand command;
        try {
            command = buildCommand(request, target, service);
        } catch (IOException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "No se pudieron preparar las wordlists: " + sample(ex.getMessage(), 300));
        }

        ToolExecutionJob job = jobs.save(new ToolExecutionJob(
                username,
                "hydra",
                target,
                writeJson(storedParameters(request, service, command)),
                command.preview()
        ));
        RuntimeLog log = new RuntimeLog();
        runtimeLogs.put(job.getId(), log);
        auditEvents.save(new AuditEvent(username, "HYDRA_ATTACK_START", target + "/" + service, remoteIp));
        CompletableFuture.runAsync(() -> runHydra(job.getId(), command, log), executor);
        return job(job.getId(), username);
    }

    public Map<String, Object> job(UUID id, String username) {
        ToolExecutionJob job = jobs.findById(id)
                .filter(item -> username.equals(item.getUsername()))
                .filter(item -> "hydra".equals(item.getTool()))
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

    public List<Map<String, Object>> recentJobs(String username) {
        return jobs.findByUsernameAndToolOrderByCreatedAtDesc(username, "hydra", PageRequest.of(0, 20)).stream()
                .map(job -> {
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("id", job.getId());
                    row.put("target", job.getTarget());
                    row.put("status", job.getStatus());
                    row.put("progress", job.getProgress());
                    row.put("phase", job.getPhase());
                    row.put("createdAt", string(job.getCreatedAt()));
                    row.put("completedAt", string(job.getCompletedAt()));
                    row.put("parameters", readJson(job.getParametersJson()));
                    row.put("result", readJson(job.getResultJson()));
                    return row;
                })
                .toList();
    }

    private void runHydra(UUID jobId, HydraCommand command, RuntimeLog log) {
        update(jobId, job -> job.markRunning("Preparando Hydra"));
        AtomicInteger attempts = new AtomicInteger();
        try {
            update(jobId, job -> job.updateProgress(8, "Lanzando Hydra"));
            Process process = new ProcessBuilder(command.command())
                    .redirectErrorStream(false)
                    .start();
            update(jobId, job -> job.updateProgress(14, "Ataque controlado en curso"));

            Future<String> stdout = executor.submit(readStream(process.getInputStream(), line -> handleHydraLine(jobId, command, log, attempts, line)));
            Future<String> stderr = executor.submit(readStream(process.getErrorStream(), line -> handleHydraLine(jobId, command, log, attempts, line)));

            boolean finished = process.waitFor(jobTimeoutSeconds, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                throw new IllegalStateException("Tiempo maximo de ejecucion superado");
            }

            String out = stdout.get(10, TimeUnit.SECONDS);
            String err = stderr.get(10, TimeUnit.SECONDS);
            int exitCode = process.exitValue();
            Map<String, Object> result = parseHydraResult(out + "\n" + err, exitCode, attempts.get(), command);
            boolean expectedFinish = exitCode == 0
                    || !((List<?>) result.getOrDefault("credentials", List.of())).isEmpty()
                    || String.valueOf(result.getOrDefault("status", "")).contains("no-valid-credentials");
            if (expectedFinish) {
                update(jobId, job -> job.markCompleted(writeJson(result)));
            } else {
                update(jobId, job -> job.markFailed("Hydra termino con codigo " + exitCode, writeJson(result)));
            }
        } catch (Exception ex) {
            Map<String, Object> result = Map.of("error", sample(ex.getMessage(), 1000));
            update(jobId, job -> job.markFailed(sample(ex.getMessage(), 1000), writeJson(result)));
        } finally {
            deleteQuietly(command.tempDir());
        }
    }

    private void handleHydraLine(UUID jobId, HydraCommand command, RuntimeLog log, AtomicInteger attempts, String line) {
        String redacted = redactHydraLine(line);
        log.add(redacted);
        if (ATTEMPT.matcher(line).find()) {
            int value = attempts.incrementAndGet();
            long total = command.credentialSpace();
            if (total > 0) {
                int progress = 15 + (int) Math.min(80, Math.floor((value * 80.0) / total));
                update(jobId, job -> job.updateProgress(progress, "Probando credenciales"));
            } else if (value % 5 == 0) {
                int progress = Math.min(95, 18 + value);
                update(jobId, job -> job.updateProgress(progress, "Probando credenciales"));
            }
        }
    }

    private HydraCommand buildCommand(HydraScanRequest request, String target, String service) throws IOException {
        Path tempDir = Files.createTempDirectory("caligo-hydra-");
        List<String> command = new ArrayList<>();
        List<String> preview = new ArrayList<>();
        command.add(hydraBinary);
        preview.add(hydraBinary);
        command.add("-I");
        preview.add("-I");

        String passwordMode = valueOrDefault(request.passwordMode(), "single");
        CredentialSource users = null;
        CredentialSource passwords = null;
        CredentialSource combo = null;
        if ("combo".equals(passwordMode)) {
            combo = comboSource(request, tempDir);
            command.add("-C");
            command.add(combo.path().toString());
            preview.add("-C");
            preview.add(combo.preview());
        } else {
            users = userSource(request, tempDir);
            passwords = passwordSource(request, tempDir);
            command.add("-L");
            command.add(users.path().toString());
            preview.add("-L");
            preview.add(users.preview());
            command.add("-P");
            command.add(passwords.path().toString());
            preview.add("-P");
            preview.add(passwords.preview());
        }

        if (request.port() != null) {
            command.add("-s");
            command.add(String.valueOf(request.port()));
            preview.add("-s");
            preview.add(String.valueOf(request.port()));
        }
        if (Boolean.TRUE.equals(request.ssl()) && !service.startsWith("https") && !service.endsWith("s")) {
            command.add("-S");
            preview.add("-S");
        }
        command.add("-t");
        command.add(String.valueOf(clamp(request.tasks(), 4, 1, 64)));
        preview.add("-t");
        preview.add(String.valueOf(clamp(request.tasks(), 4, 1, 64)));
        command.add("-w");
        command.add(String.valueOf(clamp(request.connectTimeoutSeconds(), 10, 3, 300)));
        preview.add("-w");
        preview.add(String.valueOf(clamp(request.connectTimeoutSeconds(), 10, 3, 300)));
        command.add("-W");
        command.add(String.valueOf(clamp(request.responseWaitSeconds(), 5, 1, 120)));
        preview.add("-W");
        preview.add(String.valueOf(clamp(request.responseWaitSeconds(), 5, 1, 120)));

        if (Boolean.TRUE.equals(request.stopOnFound())) {
            command.add("-f");
            preview.add("-f");
        }
        if (Boolean.TRUE.equals(request.exitOnFirstHost())) {
            command.add("-F");
            preview.add("-F");
        }
        if (Boolean.TRUE.equals(request.loopUsers())) {
            command.add("-u");
            preview.add("-u");
        }
        if (Boolean.TRUE.equals(request.debugVerbose())) {
            command.add("-vV");
            preview.add("-vV");
        } else if (Boolean.TRUE.equals(request.verboseAttempts())) {
            command.add("-V");
            preview.add("-V");
        }

        command.add(target);
        preview.add(target);
        command.add(service);
        preview.add(service);
        Optional<String> moduleArgument = moduleArgument(request, service);
        moduleArgument.ifPresent(value -> {
            command.add(value);
            preview.add(redactModuleArgument(value));
        });

        long credentialSpace = credentialSpace(users, passwords, combo);
        return new HydraCommand(command, preview(preview), tempDir, credentialSpace, count(users), count(passwords), count(combo));
    }

    private CredentialSource userSource(HydraScanRequest request, Path tempDir) throws IOException {
        String mode = valueOrDefault(request.usernameMode(), "single");
        if ("file".equals(mode)) {
            Path path = allowedWordlist(request.usernameFile(), "wordlist de usuarios");
            return new CredentialSource(path, path.toString(), safeLineCount(path));
        }
        if ("list".equals(mode)) {
            List<String> values = lines(request.usernames(), "lista de usuarios", 5000);
            return writeTempList(tempDir, "users.txt", values, "<inline-users:" + values.size() + ">");
        }
        String username = valueOrDefault(request.username(), "");
        if (!hasText(username)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "El usuario es obligatorio");
        }
        return writeTempList(tempDir, "users.txt", List.of(username), "<inline-users:1>");
    }

    private CredentialSource passwordSource(HydraScanRequest request, Path tempDir) throws IOException {
        String mode = valueOrDefault(request.passwordMode(), "single");
        if ("file".equals(mode)) {
            Path path = allowedWordlist(request.passwordFile(), "wordlist de passwords");
            return new CredentialSource(path, path.toString(), safeLineCount(path));
        }
        if ("list".equals(mode)) {
            List<String> values = lines(request.passwords(), "lista de passwords", 10000);
            return writeTempList(tempDir, "passwords.txt", values, "<inline-passwords:" + values.size() + ">");
        }
        String password = valueOrDefault(request.password(), "");
        if (!hasText(password)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "La password es obligatoria");
        }
        return writeTempList(tempDir, "passwords.txt", List.of(password), "<inline-passwords:1>");
    }

    private CredentialSource comboSource(HydraScanRequest request, Path tempDir) throws IOException {
        if (hasText(request.comboFile())) {
            Path path = allowedWordlist(request.comboFile(), "combo login:pass");
            return new CredentialSource(path, path.toString(), safeLineCount(path));
        }
        List<String> pairs = lines(request.passwords(), "combo login:pass", 10000);
        boolean invalid = pairs.stream().anyMatch(line -> !line.contains(":"));
        if (invalid) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "El modo combo requiere lineas login:password");
        }
        return writeTempList(tempDir, "combo.txt", pairs, "<inline-combo:" + pairs.size() + ">");
    }

    private CredentialSource writeTempList(Path tempDir, String filename, List<String> values, String preview) throws IOException {
        Path path = tempDir.resolve(filename);
        Files.write(path, values, StandardCharsets.UTF_8);
        return new CredentialSource(path, preview, values.size());
    }

    private Optional<String> moduleArgument(HydraScanRequest request, String service) {
        if (service.endsWith("post-form") || service.endsWith("get-form")) {
            String path = valueOrDefault(request.httpPath(), "/login");
            String parameters = valueOrDefault(request.httpParameters(), "username=^USER^&password=^PASS^");
            String condition = hasText(request.httpFailCondition())
                    ? request.httpFailCondition().trim()
                    : valueOrDefault(request.httpSuccessCondition(), "F=incorrect");
            validateModuleText(path, "path HTTP");
            validateModuleText(parameters, "parametros HTTP");
            validateModuleText(condition, "condicion HTTP");
            if (!parameters.contains("^USER^") || !parameters.contains("^PASS^")) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Los parametros HTTP deben incluir ^USER^ y ^PASS^");
            }
            if (!condition.startsWith("F=") && !condition.startsWith("S=")) {
                condition = "F=" + condition;
            }
            return Optional.of(path + ":" + parameters + ":" + condition);
        }
        if (hasText(request.moduleOptions())) {
            String value = request.moduleOptions().trim();
            validateModuleText(value, "opciones del modulo");
            return Optional.of(value);
        }
        return Optional.empty();
    }

    private Map<String, Object> parseHydraResult(String output, int exitCode, int attempts, HydraCommand command) {
        List<Map<String, Object>> credentials = new ArrayList<>();
        Matcher matcher = FOUND_CREDENTIAL.matcher(output);
        while (matcher.find() && credentials.size() < 200) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("port", valueOrDefault(matcher.group(1), ""));
            item.put("service", matcher.group(2));
            item.put("host", matcher.group(3));
            item.put("login", matcher.group(5).trim());
            item.put("password", matcher.group(6).trim());
            credentials.add(item);
        }
        String redacted = redactHydraLine(output);
        String status = credentials.isEmpty()
                ? (output.toLowerCase(Locale.ROOT).contains("0 valid password") ? "no-valid-credentials" : "finished")
                : "credentials-found";
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("validCredentials", credentials.size());
        summary.put("attemptsObserved", attempts);
        summary.put("credentialSpace", command.credentialSpace());
        summary.put("usernameCount", command.usernameCount());
        summary.put("passwordCount", command.passwordCount());
        summary.put("comboCount", command.comboCount());
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("exitCode", exitCode);
        result.put("status", status);
        result.put("summary", summary);
        result.put("credentials", credentials);
        result.put("output", sample(redacted, 16000));
        return result;
    }

    private Map<String, Object> storedParameters(HydraScanRequest request, String service, HydraCommand command) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("service", service);
        map.put("port", request.port());
        map.put("ssl", Boolean.TRUE.equals(request.ssl()));
        map.put("usernameMode", valueOrDefault(request.usernameMode(), "single"));
        map.put("username", sample(valueOrDefault(request.username(), ""), 160));
        map.put("usernameFile", safeStoredPath(request.usernameFile()));
        map.put("usernameCount", command.usernameCount());
        map.put("passwordMode", valueOrDefault(request.passwordMode(), "single"));
        map.put("password", hasText(request.password()) ? "<redacted>" : "");
        map.put("passwordFile", safeStoredPath(request.passwordFile()));
        map.put("comboFile", safeStoredPath(request.comboFile()));
        map.put("passwordCount", command.passwordCount());
        map.put("comboCount", command.comboCount());
        map.put("tasks", clamp(request.tasks(), 4, 1, 64));
        map.put("connectTimeoutSeconds", clamp(request.connectTimeoutSeconds(), 10, 3, 300));
        map.put("responseWaitSeconds", clamp(request.responseWaitSeconds(), 5, 1, 120));
        map.put("stopOnFound", Boolean.TRUE.equals(request.stopOnFound()));
        map.put("exitOnFirstHost", Boolean.TRUE.equals(request.exitOnFirstHost()));
        map.put("loopUsers", Boolean.TRUE.equals(request.loopUsers()));
        map.put("verboseAttempts", Boolean.TRUE.equals(request.verboseAttempts()));
        map.put("debugVerbose", Boolean.TRUE.equals(request.debugVerbose()));
        map.put("httpPath", service.endsWith("form") ? valueOrDefault(request.httpPath(), "/login") : "");
        map.put("httpParameters", service.endsWith("form") ? redactModuleArgument(valueOrDefault(request.httpParameters(), "")) : "");
        map.put("condition", service.endsWith("form") ? valueOrDefault(firstText(request.httpFailCondition(), request.httpSuccessCondition()), "") : "");
        map.put("credentialSpace", command.credentialSpace());
        return map;
    }

    private List<Map<String, Object>> wordlists() {
        List<Map<String, Object>> values = new ArrayList<>();
        for (Path root : wordlistRoots) {
            collectWordlists(root, root, values, 0);
        }
        return values;
    }

    private void collectWordlists(Path root, Path current, List<Map<String, Object>> values, int depth) {
        if (values.size() >= 160 || depth > 4 || !Files.isDirectory(current) || !Files.isReadable(current)) {
            return;
        }
        try (Stream<Path> stream = Files.list(current)) {
            for (Path path : stream.toList()) {
                if (values.size() >= 160) {
                    return;
                }
                if (Files.isRegularFile(path) && Files.isReadable(path) && looksLikeWordlist(path)) {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("path", path.toString());
                    item.put("label", root.relativize(path).toString());
                    item.put("sizeBytes", size(path));
                    item.put("root", root.toString());
                    values.add(item);
                } else if (Files.isDirectory(path) && !Files.isSymbolicLink(path)) {
                    collectWordlists(root, path, values, depth + 1);
                }
            }
        } catch (Exception ignored) {
            // Some distro wordlist folders contain unreadable entries. Skip them in capabilities.
        }
    }

    private boolean looksLikeWordlist(Path path) {
        String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
        return name.endsWith(".txt") || name.endsWith(".lst") || name.endsWith(".dic")
                || name.endsWith(".wordlist") || !name.contains(".");
    }

    private long size(Path path) {
        try {
            return Files.size(path);
        } catch (IOException ex) {
            return 0;
        }
    }

    private Path allowedWordlist(String rawPath, String label) {
        if (!hasText(rawPath)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Falta " + label);
        }
        Path requested = Path.of(rawPath.trim()).toAbsolutePath().normalize();
        boolean allowed = wordlistRoots.stream().anyMatch(root -> requested.startsWith(root.toAbsolutePath().normalize()));
        if (!allowed || !Files.isRegularFile(requested) || !Files.isReadable(requested)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "El fichero indicado no esta permitido o no es legible");
        }
        return requested;
    }

    private long safeLineCount(Path path) {
        try (Stream<String> lines = Files.lines(path, StandardCharsets.UTF_8)) {
            long count = lines.limit(1_000_001L).count();
            return count > 1_000_000L ? 0 : count;
        } catch (Exception ex) {
            return 0;
        }
    }

    private String sanitizeTarget(String rawTarget) {
        String target = valueOrDefault(rawTarget, "");
        if (!hasText(target)) {
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

    private String sanitizeService(String rawService) {
        String service = valueOrDefault(rawService, "ssh").toLowerCase(Locale.ROOT);
        if (!SAFE_SERVICE.matcher(service).matches() || !SERVICES.contains(service)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Servicio Hydra no permitido en Caligo");
        }
        return service;
    }

    private boolean isPrivateOrLocalTarget(String target) {
        String host = target.toLowerCase(Locale.ROOT);
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

    private List<String> lines(String value, String label, int maxLines) {
        if (!hasText(value)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Falta " + label);
        }
        List<String> items = value.lines()
                .map(String::trim)
                .filter(item -> !item.isBlank())
                .limit(maxLines + 1L)
                .toList();
        if (items.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "La " + label + " esta vacia");
        }
        if (items.size() > maxLines) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "La " + label + " supera el limite de " + maxLines + " lineas");
        }
        boolean invalid = items.stream().anyMatch(item -> item.indexOf('\0') >= 0);
        if (invalid) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "La " + label + " contiene caracteres no validos");
        }
        return items;
    }

    private void validateModuleText(String value, String label) {
        if (value.indexOf('\0') >= 0 || value.contains("\n") || value.contains("\r")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Las " + label + " no pueden contener saltos de linea");
        }
    }

    private String hydraVersion() {
        if (!commandAvailable(hydraBinary)) {
            return "";
        }
        try {
            Process process = new ProcessBuilder(hydraBinary, "-h").redirectErrorStream(true).start();
            Future<String> stdout = executor.submit(readStream(process.getInputStream(), line -> {
            }));
            process.waitFor(5, TimeUnit.SECONDS);
            String output = stdout.get(2, TimeUnit.SECONDS);
            return output.lines().findFirst().orElse("");
        } catch (Exception ex) {
            return "";
        }
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
                "examples", List.of("192.168.0.1", "10.0.0.5", "127.0.0.1", "host.local")
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

    private String serviceDescription(String service) {
        if (service.contains("form")) {
            return "Modulo web con ^USER^ y ^PASS^.";
        }
        if (service.startsWith("http")) {
            return "Autenticacion HTTP basica o endpoint web.";
        }
        return "Modulo Hydra " + service + " para laboratorio autorizado.";
    }

    private List<Path> parseRoots(String roots) {
        return Stream.of(valueOrDefault(roots, "").split(","))
                .map(String::trim)
                .filter(item -> !item.isBlank())
                .map(Path::of)
                .map(path -> path.toAbsolutePath().normalize())
                .toList();
    }

    private int parseOctet(String value) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException ex) {
            return 999;
        }
    }

    private int clamp(Integer value, int fallback, int min, int max) {
        int number = value == null ? fallback : value;
        return Math.max(min, Math.min(max, number));
    }

    private long credentialSpace(CredentialSource users, CredentialSource passwords, CredentialSource combo) {
        if (combo != null) {
            return Math.max(0, combo.count());
        }
        long userCount = count(users);
        long passwordCount = count(passwords);
        if (userCount <= 0 || passwordCount <= 0) {
            return 0;
        }
        long total = userCount * passwordCount;
        return total < 0 ? 0 : total;
    }

    private long count(CredentialSource source) {
        return source == null ? 0 : source.count();
    }

    private String firstText(String first, String second) {
        return hasText(first) ? first : valueOrDefault(second, "");
    }

    private String safeStoredPath(String path) {
        if (!hasText(path)) {
            return "";
        }
        return sample(path.trim(), 320);
    }

    private String preview(List<String> command) {
        return String.join(" ", command.stream().map(this::quotePreview).toList());
    }

    private String quotePreview(String value) {
        if (value.matches("^[A-Za-z0-9_./:<>,:-]+$")) {
            return value;
        }
        return "'" + value.replace("'", "'\\''") + "'";
    }

    private String redactHydraLine(String value) {
        if (value == null) {
            return "";
        }
        return value
                .replaceAll("(?i)(password\\s*:\\s*)\\S+", "$1<redacted>")
                .replaceAll("(?i)(pass\\s+\\\")([^\\\"]*)(\\\")", "$1<redacted>$3")
                .replaceAll("(?i)(pass=)[^\\s&]+", "$1<redacted>")
                .replaceAll("(?i)(password=)[^\\s&]+", "$1<redacted>")
                .replaceAll("(?i)(pwd=)[^\\s&]+", "$1<redacted>");
    }

    private String redactModuleArgument(String value) {
        return redactHydraLine(value)
                .replace("^PASS^", "<PASS>");
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

    private void deleteQuietly(Path path) {
        if (path == null || !Files.exists(path)) {
            return;
        }
        try (Stream<Path> stream = Files.walk(path)) {
            stream.sorted((left, right) -> right.compareTo(left)).forEach(item -> {
                try {
                    Files.deleteIfExists(item);
                } catch (IOException ignored) {
                    // Temporary material is best-effort cleanup.
                }
            });
        } catch (IOException ignored) {
            // Temporary material is best-effort cleanup.
        }
    }

    private record CredentialSource(Path path, String preview, long count) {
    }

    private record HydraCommand(
            List<String> command,
            String preview,
            Path tempDir,
            long credentialSpace,
            long usernameCount,
            long passwordCount,
            long comboCount
    ) {
    }

    private static class RuntimeLog {
        private final List<String> lines = Collections.synchronizedList(new ArrayList<>());

        void add(String line) {
            if (line == null || line.isBlank()) {
                return;
            }
            lines.add(line);
            while (lines.size() > 100) {
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
