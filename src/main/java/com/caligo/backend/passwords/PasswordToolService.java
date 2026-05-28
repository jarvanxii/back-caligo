package com.caligo.backend.passwords;

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
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
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
import java.util.stream.Stream;

@Service
public class PasswordToolService {

    private static final int INLINE_HASH_LIMIT = 1_000;
    private static final int INLINE_WORD_LIMIT = 50_000;
    private static final long CRUNCH_MAX_LINES = 500_000L;
    private static final Pattern SAFE_NAME = Pattern.compile("^[A-Za-z0-9_.-]{1,80}$");
    private static final Pattern HASHCAT_PROGRESS = Pattern.compile("Progress\\.+:\\s+(\\d+)/(\\d+)\\s+\\((\\d+(?:\\.\\d+)?)%\\)", Pattern.CASE_INSENSITIVE);
    private static final Pattern IPV4 = Pattern.compile("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");

    private final ToolExecutionJobRepository jobs;
    private final AuditEventRepository auditEvents;
    private final ObjectMapper objectMapper;
    private final ExecutorService executor;
    private final Map<UUID, RuntimeLog> runtimeLogs = new ConcurrentHashMap<>();
    private final String johnBinary;
    private final String hashcatBinary;
    private final String hashidBinary;
    private final String crunchBinary;
    private final String cewlBinary;
    private final long timeoutSeconds;
    private final int maxOutputBytes;
    private final boolean allowExternalTargets;
    private final List<Path> wordlistRoots;
    private final Path generatedWordlistRoot;

    public PasswordToolService(
            ToolExecutionJobRepository jobs,
            AuditEventRepository auditEvents,
            ObjectMapper objectMapper,
            @Value("${caligo.passwords.john.binary:john}") String johnBinary,
            @Value("${caligo.passwords.hashcat.binary:hashcat}") String hashcatBinary,
            @Value("${caligo.passwords.hashid.binary:hashid}") String hashidBinary,
            @Value("${caligo.passwords.crunch.binary:crunch}") String crunchBinary,
            @Value("${caligo.passwords.cewl.binary:cewl}") String cewlBinary,
            @Value("${caligo.passwords.timeout-seconds:1800}") long timeoutSeconds,
            @Value("${caligo.passwords.max-output-bytes:1048576}") int maxOutputBytes,
            @Value("${caligo.passwords.allow-external-targets:false}") boolean allowExternalTargets,
            @Value("${caligo.passwords.wordlist-roots:/opt/caligo/wordlists,/usr/share/wordlists}") String wordlistRoots,
            @Value("${caligo.passwords.generated-wordlist-root:/opt/caligo/wordlists/generated}") String generatedWordlistRoot
    ) {
        this.jobs = jobs;
        this.auditEvents = auditEvents;
        this.objectMapper = objectMapper;
        this.johnBinary = johnBinary;
        this.hashcatBinary = hashcatBinary;
        this.hashidBinary = hashidBinary;
        this.crunchBinary = crunchBinary;
        this.cewlBinary = cewlBinary;
        this.timeoutSeconds = Math.max(30, timeoutSeconds);
        this.maxOutputBytes = Math.max(8192, maxOutputBytes);
        this.allowExternalTargets = allowExternalTargets;
        this.wordlistRoots = parseRoots(wordlistRoots);
        this.generatedWordlistRoot = Path.of(generatedWordlistRoot).toAbsolutePath().normalize();
        this.executor = Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "caligo-password-worker");
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
        response.put("tools", List.of(
                tool("john", "John the Ripper", commandAvailable(johnBinary), version(johnBinary)),
                tool("hashcat", "Hashcat", commandAvailable(hashcatBinary), version(hashcatBinary)),
                tool("hashid", "hashID", commandAvailable(hashidBinary), version(hashidBinary)),
                tool("crunch", "Crunch", commandAvailable(crunchBinary), version(crunchBinary)),
                tool("cewl", "CeWL", commandAvailable(cewlBinary), version(cewlBinary))
        ));
        response.put("wordlists", wordlists());
        response.put("johnFormats", johnFormats());
        response.put("hashcatModes", hashcatModes());
        response.put("scope", Map.of(
                "offlineCracking", true,
                "allowExternalTargets", allowExternalTargets,
                "generatedWordlistRoot", generatedWordlistRoot.toString()
        ));
        response.put("defaults", Map.of(
                "hashes", "5f4dcc3b5aa765d61d8327deb882cf99",
                "wordlistText", "password\npassword123\npepito53\ncaligo",
                "hashFormat", "raw-md5",
                "hashcatMode", "0",
                "attackMode", "wordlist",
                "mask", "?l?l?l?l?d?d"
        ));
        return response;
    }

    public Map<String, Object> identify(HashIdentifyRequest request) {
        String hash = valueOrDefault(request.hash(), "");
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("hash", sample(hash, 160));
        response.put("tool", "hashid");
        response.put("available", commandAvailable(hashidBinary));
        if (commandAvailable(hashidBinary)) {
            CommandResult result = runCommand(List.of(hashidBinary, hash), Duration.ofSeconds(10));
            response.put("output", sample(result.output(), 12000));
            response.put("exitCode", result.exitCode());
            response.put("candidates", parseHashId(result.output()));
        } else {
            response.put("output", "");
            response.put("candidates", heuristicCandidates(hash));
        }
        response.put("heuristics", heuristicCandidates(hash));
        return response;
    }

    public Map<String, Object> startCrack(String rawTool, PasswordCrackRequest request, String username, String remoteIp) {
        String tool = normalizeTool(rawTool);
        if (!List.of("john", "hashcat").contains(tool)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Herramienta de cracking no registrada");
        }
        String binary = "john".equals(tool) ? johnBinary : hashcatBinary;
        if (!commandAvailable(binary)) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, tool + " no esta instalado o no esta en PATH");
        }
        CrackCommand command;
        try {
            command = "john".equals(tool) ? johnCommand(request) : hashcatCommand(request);
        } catch (IOException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "No se pudo preparar el material temporal: " + sample(ex.getMessage(), 300));
        }

        ToolExecutionJob job = jobs.save(new ToolExecutionJob(
                username,
                tool,
                command.target(),
                writeJson(command.parameters()),
                command.preview()
        ));
        RuntimeLog log = new RuntimeLog();
        runtimeLogs.put(job.getId(), log);
        auditEvents.save(new AuditEvent(username, "PASSWORD_" + tool.toUpperCase(Locale.ROOT) + "_START", command.target(), remoteIp));
        CompletableFuture.runAsync(() -> runCrack(job.getId(), tool, command, log), executor);
        return job(tool, job.getId(), username);
    }

    public Map<String, Object> startGenerator(String rawTool, WordlistGenerateRequest request, String username, String remoteIp) {
        String tool = normalizeTool(rawTool);
        if (!List.of("crunch", "cewl").contains(tool)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Generador no registrado");
        }
        String binary = "crunch".equals(tool) ? crunchBinary : cewlBinary;
        if (!commandAvailable(binary)) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, tool + " no esta instalado o no esta en PATH");
        }
        GeneratorCommand command;
        try {
            command = "crunch".equals(tool) ? crunchCommand(request) : cewlCommand(request);
        } catch (IOException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "No se pudo preparar la salida: " + sample(ex.getMessage(), 300));
        }

        ToolExecutionJob job = jobs.save(new ToolExecutionJob(
                username,
                tool,
                command.target(),
                writeJson(command.parameters()),
                command.preview()
        ));
        RuntimeLog log = new RuntimeLog();
        runtimeLogs.put(job.getId(), log);
        auditEvents.save(new AuditEvent(username, "PASSWORD_" + tool.toUpperCase(Locale.ROOT) + "_START", command.target(), remoteIp));
        CompletableFuture.runAsync(() -> runGenerator(job.getId(), command, log), executor);
        return job(tool, job.getId(), username);
    }

    public Map<String, Object> job(String rawTool, UUID id, String username) {
        String tool = normalizeTool(rawTool);
        ToolExecutionJob job = jobs.findById(id)
                .filter(item -> username.equals(item.getUsername()))
                .filter(item -> tool.equals(item.getTool()))
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

    public List<Map<String, Object>> recentJobs(String rawTool, String username) {
        String tool = normalizeTool(rawTool);
        return jobs.findByUsernameAndToolOrderByCreatedAtDesc(username, tool, PageRequest.of(0, 20)).stream()
                .map(job -> {
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("id", job.getId());
                    row.put("target", job.getTarget());
                    row.put("tool", job.getTool());
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

    public List<Map<String, Object>> wordlists() {
        List<Map<String, Object>> values = new ArrayList<>();
        List<Path> roots = new ArrayList<>(wordlistRoots);
        if (roots.stream().noneMatch(root -> generatedWordlistRoot.startsWith(root.toAbsolutePath().normalize()))) {
            roots.add(generatedWordlistRoot);
        }
        for (Path root : roots) {
            collectWordlists(root, root, values, 0);
        }
        values.sort(Comparator.comparing(item -> String.valueOf(item.get("label"))));
        return values.size() > 220 ? values.subList(0, 220) : values;
    }

    private CrackCommand johnCommand(PasswordCrackRequest request) throws IOException {
        Path tempDir = Files.createTempDirectory("caligo-john-");
        List<String> hashes = lines(request.hashes(), "hashes", INLINE_HASH_LIMIT);
        Path hashFile = tempDir.resolve("hashes.txt");
        Files.write(hashFile, hashes, StandardCharsets.UTF_8);
        Path potFile = tempDir.resolve("john.pot");
        String format = valueOrDefault(request.hashFormat(), "auto");
        WordSource wordSource = wordSource(request, tempDir);

        List<String> command = new ArrayList<>();
        command.add(johnBinary);
        if (!"auto".equals(format)) {
            command.add("--format=" + format);
        }
        command.add("--wordlist=" + wordSource.path());
        command.add("--pot=" + potFile);
        command.add("--session=caligo-" + UUID.randomUUID().toString().substring(0, 8));
        command.add(hashFile.toString());

        List<String> showCommand = new ArrayList<>();
        showCommand.add(johnBinary);
        showCommand.add("--show");
        if (!"auto".equals(format)) {
            showCommand.add("--format=" + format);
        }
        showCommand.add("--pot=" + potFile);
        showCommand.add(hashFile.toString());

        Map<String, Object> parameters = new LinkedHashMap<>();
        parameters.put("format", format);
        parameters.put("hashCount", hashes.size());
        parameters.put("wordlist", wordSource.preview());
        parameters.put("wordCount", wordSource.count());
        parameters.put("attackMode", "wordlist");
        return new CrackCommand(command, showCommand, tempDir, "john / " + hashes.size() + " hashes", preview(command, true), parameters);
    }

    private CrackCommand hashcatCommand(PasswordCrackRequest request) throws IOException {
        Path tempDir = Files.createTempDirectory("caligo-hashcat-");
        List<String> hashes = lines(request.hashes(), "hashes", INLINE_HASH_LIMIT);
        Path hashFile = tempDir.resolve("hashes.txt");
        Files.write(hashFile, hashes, StandardCharsets.UTF_8);
        Path potFile = tempDir.resolve("hashcat.pot");
        Path outFile = tempDir.resolve("hashcat.out");
        String mode = valueOrDefault(request.hashcatMode(), "0");
        if (!mode.matches("\\d{1,8}")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Modo Hashcat no valido");
        }
        String attackMode = valueOrDefault(request.attackMode(), "wordlist");

        List<String> command = new ArrayList<>();
        command.add(hashcatBinary);
        command.add("-m");
        command.add(mode);
        command.add("-a");
        command.add("mask".equals(attackMode) ? "3" : "0");
        command.add("--status");
        command.add("--status-timer");
        command.add("5");
        command.add("--potfile-path");
        command.add(potFile.toString());
        command.add("--outfile");
        command.add(outFile.toString());
        command.add("--outfile-format");
        command.add("2,3");
        command.add("--restore-disable");
        if (Boolean.TRUE.equals(request.usernameFormat())) {
            command.add("--username");
        }
        command.add(hashFile.toString());

        WordSource wordSource = null;
        String mask = "";
        if ("mask".equals(attackMode)) {
            mask = sanitizeMask(valueOrDefault(request.mask(), "?l?l?l?l?d?d"));
            command.add(mask);
        } else {
            wordSource = wordSource(request, tempDir);
            command.add(wordSource.path().toString());
        }

        Map<String, Object> parameters = new LinkedHashMap<>();
        parameters.put("hashcatMode", mode);
        parameters.put("attackMode", attackMode);
        parameters.put("hashCount", hashes.size());
        parameters.put("wordlist", wordSource == null ? "" : wordSource.preview());
        parameters.put("wordCount", wordSource == null ? 0 : wordSource.count());
        parameters.put("mask", mask);
        parameters.put("usernameFormat", Boolean.TRUE.equals(request.usernameFormat()));
        parameters.put("outfile", outFile.toString());
        return new CrackCommand(command, List.of(), tempDir, "hashcat / " + hashes.size() + " hashes", preview(command, true), parameters);
    }

    private GeneratorCommand crunchCommand(WordlistGenerateRequest request) throws IOException {
        Files.createDirectories(generatedWordlistRoot);
        int min = clamp(request.minLength(), 4, 1, 8);
        int max = clamp(request.maxLength(), Math.max(min, 6), min, 8);
        String charset = valueOrDefault(request.charset(), "abcdefghijklmnopqrstuvwxyz0123456789");
        validateCharset(charset);
        long estimated = estimateCrunchLines(charset.length(), min, max);
        if (estimated > CRUNCH_MAX_LINES) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "La mascara generaria " + estimated + " lineas; limite " + CRUNCH_MAX_LINES);
        }
        Path output = generatedPath(request.outputName(), "crunch-" + min + "-" + max + ".txt");
        List<String> command = List.of(crunchBinary, String.valueOf(min), String.valueOf(max), charset, "-o", output.toString());
        Map<String, Object> parameters = new LinkedHashMap<>();
        parameters.put("minLength", min);
        parameters.put("maxLength", max);
        parameters.put("charset", charset);
        parameters.put("estimatedLines", estimated);
        parameters.put("output", output.toString());
        return new GeneratorCommand(command, null, output, "crunch / " + output.getFileName(), preview(command, false), parameters);
    }

    private GeneratorCommand cewlCommand(WordlistGenerateRequest request) throws IOException {
        Files.createDirectories(generatedWordlistRoot);
        String url = valueOrDefault(request.url(), "");
        URI uri;
        try {
            uri = URI.create(url);
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "URL CeWL no valida");
        }
        if (!List.of("http", "https").contains(String.valueOf(uri.getScheme()).toLowerCase(Locale.ROOT))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "CeWL requiere http o https");
        }
        if (!allowExternalTargets && !isPrivateOrLocalTarget(uri.getHost())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "CeWL solo acepta objetivos privados/locales salvo configuracion explicita");
        }
        int depth = clamp(request.depth(), 2, 1, 5);
        int minWordLength = clamp(request.minWordLength(), 5, 3, 12);
        Path output = generatedPath(request.outputName(), "cewl-" + safeFilename(uri.getHost()) + ".txt");
        List<String> command = new ArrayList<>();
        command.add(cewlBinary);
        command.add(url);
        command.add("-d");
        command.add(String.valueOf(depth));
        command.add("-m");
        command.add(String.valueOf(minWordLength));
        command.add("-w");
        command.add(output.toString());
        if (Boolean.TRUE.equals(request.withNumbers())) {
            command.add("--with-numbers");
        }
        Map<String, Object> parameters = new LinkedHashMap<>();
        parameters.put("url", url);
        parameters.put("depth", depth);
        parameters.put("minWordLength", minWordLength);
        parameters.put("withNumbers", Boolean.TRUE.equals(request.withNumbers()));
        parameters.put("output", output.toString());
        return new GeneratorCommand(command, null, output, "cewl / " + safeFilename(uri.getHost()), preview(command, false), parameters);
    }

    private void runCrack(UUID jobId, String tool, CrackCommand command, RuntimeLog log) {
        update(jobId, job -> job.markRunning("Preparando " + tool));
        try {
            update(jobId, job -> job.updateProgress(8, "Lanzando " + tool));
            Process process = new ProcessBuilder(command.command()).redirectErrorStream(false).start();
            update(jobId, job -> job.updateProgress(18, "Cracking offline en curso"));
            Future<String> stdout = executor.submit(readStream(process.getInputStream(), line -> handleCrackLine(jobId, tool, log, line)));
            Future<String> stderr = executor.submit(readStream(process.getErrorStream(), line -> handleCrackLine(jobId, tool, log, line)));
            boolean finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                throw new IllegalStateException("Tiempo maximo de ejecucion superado");
            }
            String out = stdout.get(10, TimeUnit.SECONDS);
            String err = stderr.get(10, TimeUnit.SECONDS);
            int exitCode = process.exitValue();
            Map<String, Object> result = "john".equals(tool)
                    ? johnResult(command, exitCode, out + "\n" + err)
                    : hashcatResult(command, exitCode, out + "\n" + err);
            boolean expected = "john".equals(tool) ? exitCode == 0 : exitCode == 0 || exitCode == 1;
            if (expected) {
                update(jobId, job -> job.markCompleted(writeJson(result)));
            } else {
                update(jobId, job -> job.markFailed(tool + " termino con codigo " + exitCode, writeJson(result)));
            }
        } catch (Exception ex) {
            Map<String, Object> result = Map.of("error", sample(ex.getMessage(), 1000));
            update(jobId, job -> job.markFailed(sample(ex.getMessage(), 1000), writeJson(result)));
        } finally {
            deleteQuietly(command.tempDir());
        }
    }

    private void runGenerator(UUID jobId, GeneratorCommand command, RuntimeLog log) {
        update(jobId, job -> job.markRunning("Generando wordlist"));
        try {
            Process process = new ProcessBuilder(command.command()).redirectErrorStream(false).start();
            update(jobId, job -> job.updateProgress(35, "Proceso en curso"));
            Future<String> stdout = executor.submit(readStream(process.getInputStream(), log::add));
            Future<String> stderr = executor.submit(readStream(process.getErrorStream(), log::add));
            boolean finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                throw new IllegalStateException("Tiempo maximo de generacion superado");
            }
            String output = stdout.get(10, TimeUnit.SECONDS) + "\n" + stderr.get(10, TimeUnit.SECONDS);
            int exitCode = process.exitValue();
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("exitCode", exitCode);
            result.put("output", sample(output, 16000));
            result.put("wordlist", wordlistInfo(command.output(), generatedWordlistRoot));
            result.put("lineCount", safeLineCount(command.output()));
            result.put("parameters", command.parameters());
            if (exitCode == 0 && Files.isRegularFile(command.output())) {
                update(jobId, job -> job.markCompleted(writeJson(result)));
            } else {
                update(jobId, job -> job.markFailed("Generador termino con codigo " + exitCode, writeJson(result)));
            }
        } catch (Exception ex) {
            Map<String, Object> result = Map.of("error", sample(ex.getMessage(), 1000));
            update(jobId, job -> job.markFailed(sample(ex.getMessage(), 1000), writeJson(result)));
        }
    }

    private void handleCrackLine(UUID jobId, String tool, RuntimeLog log, String line) {
        log.add(line);
        if ("hashcat".equals(tool)) {
            Matcher matcher = HASHCAT_PROGRESS.matcher(line);
            if (matcher.find()) {
                int progress = (int) Math.floor(Double.parseDouble(matcher.group(3)));
                update(jobId, job -> job.updateProgress(Math.max(18, Math.min(98, progress)), "Hashcat en curso"));
            }
        } else if (!line.isBlank()) {
            update(jobId, job -> job.updateProgress(45, "John en curso"));
        }
    }

    private Map<String, Object> johnResult(CrackCommand command, int exitCode, String output) {
        String showOutput = "";
        if (!command.showCommand().isEmpty()) {
            showOutput = runCommand(command.showCommand(), Duration.ofSeconds(30)).output();
        }
        List<Map<String, Object>> cracked = parseCracked(showOutput);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("exitCode", exitCode);
        result.put("status", cracked.isEmpty() ? "finished" : "cracked");
        result.put("cracked", cracked);
        result.put("summary", Map.of("cracked", cracked.size()));
        result.put("output", sample(output, 16000));
        result.put("showOutput", sample(showOutput, 16000));
        return result;
    }

    private Map<String, Object> hashcatResult(CrackCommand command, int exitCode, String output) {
        List<Map<String, Object>> cracked = parseHashcatOutfile(command.parameters().get("outfile"));
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("exitCode", exitCode);
        result.put("status", cracked.isEmpty() ? "finished" : "cracked");
        result.put("cracked", cracked);
        result.put("summary", Map.of("cracked", cracked.size()));
        result.put("output", sample(output, 16000));
        return result;
    }

    private List<Map<String, Object>> parseCracked(String output) {
        List<Map<String, Object>> values = new ArrayList<>();
        for (String line : valueOrDefault(output, "").lines().toList()) {
            String trimmed = line.trim();
            if (trimmed.isBlank() || trimmed.matches("^\\d+ password hash.*") || !trimmed.contains(":")) {
                continue;
            }
            String[] parts = trimmed.split(":", 2);
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("hash", sample(parts[0], 220));
            item.put("password", sample(parts[1], 220));
            values.add(item);
            if (values.size() >= 500) {
                break;
            }
        }
        return values;
    }

    private List<Map<String, Object>> parseHashcatOutfile(Object rawPath) {
        if (rawPath == null) {
            return List.of();
        }
        Path path = Path.of(String.valueOf(rawPath));
        if (!Files.isRegularFile(path)) {
            return List.of();
        }
        try (Stream<String> stream = Files.lines(path, StandardCharsets.UTF_8)) {
            List<Map<String, Object>> values = new ArrayList<>();
            for (String line : stream.limit(500).toList()) {
                String[] parts = line.split(":", 2);
                if (parts.length < 2) {
                    continue;
                }
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("hash", sample(parts[0], 220));
                item.put("password", sample(parts[1], 220));
                values.add(item);
            }
            return values;
        } catch (IOException ex) {
            return List.of();
        }
    }

    private WordSource wordSource(PasswordCrackRequest request, Path tempDir) throws IOException {
        if (hasText(request.wordlistFile())) {
            Path path = allowedWordlist(request.wordlistFile(), "wordlist");
            return new WordSource(path, path.toString(), safeLineCount(path));
        }
        List<String> words = lines(request.wordlistText(), "wordlist pegada", INLINE_WORD_LIMIT);
        Path path = tempDir.resolve("wordlist.txt");
        Files.write(path, words, StandardCharsets.UTF_8);
        return new WordSource(path, "<inline-wordlist:" + words.size() + ">", words.size());
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
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "La lista de " + label + " esta vacia");
        }
        if (items.size() > maxLines) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "La lista de " + label + " supera " + maxLines + " lineas");
        }
        boolean invalid = items.stream().anyMatch(item -> item.indexOf('\0') >= 0);
        if (invalid) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "La lista de " + label + " contiene caracteres no validos");
        }
        return items;
    }

    private Path allowedWordlist(String rawPath, String label) {
        Path requested = Path.of(valueOrDefault(rawPath, "")).toAbsolutePath().normalize();
        boolean allowed = wordlistRoots.stream().anyMatch(root -> requested.startsWith(root.toAbsolutePath().normalize()))
                || requested.startsWith(generatedWordlistRoot);
        if (!allowed || !Files.isRegularFile(requested) || !Files.isReadable(requested)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "El fichero " + label + " no esta permitido o no es legible");
        }
        return requested;
    }

    private void collectWordlists(Path root, Path current, List<Map<String, Object>> values, int depth) {
        if (values.size() >= 240 || depth > 6 || !Files.isDirectory(current) || !Files.isReadable(current)) {
            return;
        }
        try (Stream<Path> stream = Files.list(current)) {
            for (Path path : stream.toList()) {
                if (values.size() >= 240) {
                    return;
                }
                if (Files.isRegularFile(path) && Files.isReadable(path) && looksLikeWordlist(path)) {
                    values.add(wordlistInfo(path, root));
                } else if (Files.isDirectory(path) && !Files.isSymbolicLink(path) && !path.getFileName().toString().equals(".git")) {
                    collectWordlists(root, path, values, depth + 1);
                }
            }
        } catch (Exception ignored) {
            // Some wordlist folders contain unreadable entries. Skip them.
        }
    }

    private Map<String, Object> wordlistInfo(Path path, Path root) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("path", path.toString());
        item.put("label", safeRelativize(root, path));
        item.put("sizeBytes", size(path));
        item.put("lineCount", safeLineCount(path));
        item.put("root", root.toString());
        return item;
    }

    private boolean looksLikeWordlist(Path path) {
        String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
        return name.endsWith(".txt") || name.endsWith(".lst") || name.endsWith(".dic")
                || name.endsWith(".wordlist") || !name.contains(".");
    }

    private List<Map<String, Object>> parseHashId(String output) {
        List<Map<String, Object>> values = new ArrayList<>();
        for (String line : valueOrDefault(output, "").lines().toList()) {
            String trimmed = line.trim();
            if (!trimmed.startsWith("[+]")) {
                continue;
            }
            String name = trimmed.replaceFirst("^\\[\\+]\\s*", "").trim();
            if (name.isBlank()) {
                continue;
            }
            values.add(Map.of("name", name));
            if (values.size() >= 30) {
                break;
            }
        }
        return values;
    }

    private List<Map<String, Object>> heuristicCandidates(String hash) {
        String value = valueOrDefault(hash, "");
        int length = value.length();
        List<Map<String, Object>> candidates = new ArrayList<>();
        if (value.matches("^[a-fA-F0-9]+$")) {
            if (length == 32) candidates.add(candidate("MD5 / NTLM", "john raw-md5 o hashcat -m 0; NTLM podria ser -m 1000"));
            if (length == 40) candidates.add(candidate("SHA1", "john raw-sha1 o hashcat -m 100"));
            if (length == 64) candidates.add(candidate("SHA-256", "john raw-sha256 o hashcat -m 1400"));
            if (length == 128) candidates.add(candidate("SHA-512", "john raw-sha512 o hashcat -m 1700"));
        }
        if (value.startsWith("$2a$") || value.startsWith("$2b$") || value.startsWith("$2y$")) {
            candidates.add(candidate("bcrypt", "john bcrypt o hashcat -m 3200"));
        }
        if (value.startsWith("$1$")) candidates.add(candidate("md5crypt", "john md5crypt o hashcat -m 500"));
        if (value.startsWith("$5$")) candidates.add(candidate("sha256crypt", "john sha256crypt o hashcat -m 7400"));
        if (value.startsWith("$6$")) candidates.add(candidate("sha512crypt", "john sha512crypt o hashcat -m 1800"));
        return candidates;
    }

    private Map<String, Object> candidate(String name, String hint) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("name", name);
        item.put("hint", hint);
        return item;
    }

    private List<Map<String, String>> johnFormats() {
        return List.of(
                option("auto", "Auto", "Deja que John intente detectar el formato."),
                option("raw-md5", "Raw MD5", "Hash MD5 hexadecimal."),
                option("raw-sha1", "Raw SHA1", "Hash SHA1 hexadecimal."),
                option("raw-sha256", "Raw SHA-256", "Hash SHA-256 hexadecimal."),
                option("raw-sha512", "Raw SHA-512", "Hash SHA-512 hexadecimal."),
                option("bcrypt", "bcrypt", "Hashes $2a$/$2b$/$2y$."),
                option("md5crypt", "md5crypt", "Hashes $1$."),
                option("sha256crypt", "sha256crypt", "Hashes $5$."),
                option("sha512crypt", "sha512crypt", "Hashes $6$."),
                option("NT", "NTLM", "Hashes NT de Windows.")
        );
    }

    private List<Map<String, String>> hashcatModes() {
        return List.of(
                option("0", "MD5", "Modo 0."),
                option("100", "SHA1", "Modo 100."),
                option("1400", "SHA2-256", "Modo 1400."),
                option("1700", "SHA2-512", "Modo 1700."),
                option("3200", "bcrypt", "Modo 3200."),
                option("500", "md5crypt", "Modo 500."),
                option("7400", "sha256crypt", "Modo 7400."),
                option("1800", "sha512crypt", "Modo 1800."),
                option("1000", "NTLM", "Modo 1000.")
        );
    }

    private Map<String, Object> tool(String id, String label, boolean available, String version) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("id", id);
        item.put("label", label);
        item.put("available", available);
        item.put("version", version);
        return item;
    }

    private Map<String, String> option(String value, String label, String description) {
        Map<String, String> item = new LinkedHashMap<>();
        item.put("value", value);
        item.put("label", label);
        item.put("description", description);
        return item;
    }

    private CommandResult runCommand(List<String> command, Duration timeout) {
        try {
            Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
            Future<String> output = executor.submit(readStream(process.getInputStream(), line -> {
            }));
            boolean finished = process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
            if (!finished) {
                process.destroyForcibly();
                return new CommandResult(-1, output.get(2, TimeUnit.SECONDS), true);
            }
            return new CommandResult(process.exitValue(), output.get(2, TimeUnit.SECONDS), false);
        } catch (Exception ex) {
            return new CommandResult(127, sample(ex.getMessage(), 1200), false);
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

    private String version(String binary) {
        if (!commandAvailable(binary)) {
            return "";
        }
        CommandResult result = runCommand(List.of(binary, "--version"), Duration.ofSeconds(5));
        String first = result.output().lines().map(String::trim).filter(line -> !line.isBlank()).findFirst().orElse("");
        if (first.toLowerCase(Locale.ROOT).contains("unknown option") || first.isBlank()) {
            first = runCommand(List.of(binary), Duration.ofSeconds(5)).output().lines().map(String::trim).filter(line -> !line.isBlank()).findFirst().orElse("");
        }
        return sample(first, 120);
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

    private String normalizeTool(String rawTool) {
        String tool = valueOrDefault(rawTool, "").toLowerCase(Locale.ROOT);
        if (!tool.matches("^[a-z0-9_-]{2,40}$")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Herramienta no valida");
        }
        return tool;
    }

    private String sanitizeMask(String mask) {
        if (!hasText(mask) || mask.length() > 80 || mask.indexOf('\0') >= 0 || mask.contains("\n") || mask.contains("\r")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Mascara Hashcat no valida");
        }
        return mask.trim();
    }

    private void validateCharset(String charset) {
        if (!hasText(charset) || charset.length() > 160 || charset.indexOf('\0') >= 0 || charset.contains("\n") || charset.contains("\r")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Charset Crunch no valido");
        }
    }

    private Path generatedPath(String outputName, String fallback) {
        String name = valueOrDefault(outputName, fallback);
        if (!SAFE_NAME.matcher(name).matches()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Nombre de salida no valido");
        }
        if (!name.endsWith(".txt") && !name.endsWith(".lst")) {
            name = name + ".txt";
        }
        return generatedWordlistRoot.resolve(name).toAbsolutePath().normalize();
    }

    private long estimateCrunchLines(int alphabetSize, int min, int max) {
        BigInteger total = BigInteger.ZERO;
        BigInteger base = BigInteger.valueOf(alphabetSize);
        for (int length = min; length <= max; length++) {
            total = total.add(base.pow(length));
            if (total.compareTo(BigInteger.valueOf(CRUNCH_MAX_LINES)) > 0) {
                return total.longValue();
            }
        }
        return total.longValue();
    }

    private boolean isPrivateOrLocalTarget(String target) {
        String host = valueOrDefault(target, "").toLowerCase(Locale.ROOT);
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
        return a == 10 || a == 127 || (a == 192 && b == 168) || (a == 172 && b >= 16 && b <= 31) || (a == 169 && b == 254);
    }

    private int parseOctet(String value) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException ex) {
            return 999;
        }
    }

    private List<Path> parseRoots(String roots) {
        return Stream.of(valueOrDefault(roots, "").split(","))
                .map(String::trim)
                .filter(item -> !item.isBlank())
                .map(Path::of)
                .map(path -> path.toAbsolutePath().normalize())
                .toList();
    }

    private String safeRelativize(Path root, Path path) {
        try {
            return root.toAbsolutePath().normalize().relativize(path.toAbsolutePath().normalize()).toString();
        } catch (Exception ex) {
            return path.getFileName().toString();
        }
    }

    private long size(Path path) {
        try {
            return Files.size(path);
        } catch (IOException ex) {
            return 0;
        }
    }

    private long safeLineCount(Path path) {
        try (Stream<String> lines = Files.lines(path, StandardCharsets.UTF_8)) {
            long count = lines.limit(1_000_001L).count();
            return count > 1_000_000L ? 0 : count;
        } catch (Exception ex) {
            return 0;
        }
    }

    private int clamp(Integer value, int fallback, int min, int max) {
        int number = value == null ? fallback : value;
        return Math.max(min, Math.min(max, number));
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

    private String preview(List<String> command, boolean hideTempPaths) {
        return String.join(" ", command.stream()
                .map(value -> hideTempPaths && value.contains("caligo-") ? "<temp>" : value)
                .map(this::quotePreview)
                .toList());
    }

    private String quotePreview(String value) {
        if (value.matches("^[A-Za-z0-9_./:<>,?=$-]+$")) {
            return value;
        }
        return "'" + value.replace("'", "'\\''") + "'";
    }

    private String safeFilename(String value) {
        return valueOrDefault(value, "target").replaceAll("[^A-Za-z0-9_.-]+", "-").replaceAll("^-+|-+$", "");
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

    private record WordSource(Path path, String preview, long count) {
    }

    private record CrackCommand(
            List<String> command,
            List<String> showCommand,
            Path tempDir,
            String target,
            String preview,
            Map<String, Object> parameters
    ) {
    }

    private record GeneratorCommand(
            List<String> command,
            Path tempDir,
            Path output,
            String target,
            String preview,
            Map<String, Object> parameters
    ) {
    }

    private record CommandResult(int exitCode, String output, boolean timedOut) {
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
