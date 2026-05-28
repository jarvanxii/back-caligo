package com.caligo.backend.osint;

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
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
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
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class OsintToolService {

    private static final Pattern SAFE_PERSON = Pattern.compile("(?U)^[\\p{L}\\p{N}][\\p{L}\\p{N} .,'_\\-]{1,139}$");
    private static final Pattern SAFE_USERNAME = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._\\-]{1,63}$");
    private static final Pattern SAFE_DOMAIN = Pattern.compile("(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,30}$");
    private static final Pattern SAFE_SOURCE = Pattern.compile("^[a-zA-Z0-9_-]{2,40}$");
    private static final Pattern EMAIL_PATTERN = Pattern.compile("[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,24}");
    private static final Pattern URL_PATTERN = Pattern.compile("https?://[^\\s\"'<>\\])}]+", Pattern.CASE_INSENSITIVE);
    private static final Pattern HOST_PATTERN = Pattern.compile("(?i)\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,30}\\b");
    private static final Set<String> JOB_TOOLS = Set.of("sherlock", "maigret", "social-analyzer", "holehe", "theharvester");
    private static final Map<String, String> PROFILE_SITES = Map.ofEntries(
            Map.entry("linkedin", "linkedin.com/in"),
            Map.entry("github", "github.com"),
            Map.entry("x", "x.com"),
            Map.entry("twitter", "twitter.com"),
            Map.entry("instagram", "instagram.com"),
            Map.entry("facebook", "facebook.com"),
            Map.entry("tiktok", "tiktok.com"),
            Map.entry("reddit", "reddit.com/user"),
            Map.entry("youtube", "youtube.com"),
            Map.entry("medium", "medium.com")
    );

    private final ToolExecutionJobRepository jobs;
    private final AuditEventRepository auditEvents;
    private final ObjectMapper objectMapper;
    private final HttpClient httpClient;
    private final ExecutorService executor;
    private final Map<UUID, RuntimeLog> runtimeLogs = new ConcurrentHashMap<>();
    private final String sherlockBinary;
    private final String maigretBinary;
    private final String socialAnalyzerBinary;
    private final String holeheBinary;
    private final String theHarvesterBinary;
    private final int maxOutputBytes;
    private final long defaultTimeoutSeconds;

    public OsintToolService(
            ToolExecutionJobRepository jobs,
            AuditEventRepository auditEvents,
            ObjectMapper objectMapper,
            @Value("${caligo.osint.sherlock.binary:sherlock}") String sherlockBinary,
            @Value("${caligo.osint.maigret.binary:maigret}") String maigretBinary,
            @Value("${caligo.osint.social-analyzer.binary:social-analyzer}") String socialAnalyzerBinary,
            @Value("${caligo.osint.holehe.binary:holehe}") String holeheBinary,
            @Value("${caligo.osint.theharvester.binary:theHarvester}") String theHarvesterBinary,
            @Value("${caligo.osint.max-output-bytes:1048576}") int maxOutputBytes,
            @Value("${caligo.osint.timeout-seconds:600}") long defaultTimeoutSeconds
    ) {
        this.jobs = jobs;
        this.auditEvents = auditEvents;
        this.objectMapper = objectMapper;
        this.sherlockBinary = sherlockBinary;
        this.maigretBinary = maigretBinary;
        this.socialAnalyzerBinary = socialAnalyzerBinary;
        this.holeheBinary = holeheBinary;
        this.theHarvesterBinary = theHarvesterBinary;
        this.maxOutputBytes = maxOutputBytes;
        this.defaultTimeoutSeconds = defaultTimeoutSeconds;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(8))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        this.executor = Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "caligo-osint-worker");
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
                Map.of(
                        "id", "profile-search",
                        "label", "Caligo People",
                        "binary", "backend-http",
                        "available", true,
                        "version", "server-side-search",
                        "description", "Busqueda publica por nombre en motores y sitios sociales."
                ),
                toolCapability("sherlock", "Sherlock", sherlockBinary, "sherlock --version", "Enumeracion de usernames en redes y plataformas publicas."),
                toolCapability("maigret", "Maigret", maigretBinary, "maigret --version", "Correlacion profunda de usernames y perfiles OSINT."),
                toolCapability("social-analyzer", "Social Analyzer", socialAnalyzerBinary, "/opt/caligo-pipx/venvs/social-analyzer/bin/python -c 'import importlib.metadata as m; print(m.version(\"social-analyzer\"))'", "Correlacion de nombres/usernames contra redes sociales."),
                toolCapability("holehe", "Holehe", holeheBinary, "/opt/caligo-pipx/venvs/holehe/bin/python -c 'import importlib.metadata as m; print(m.version(\"holehe\"))'", "Comprobacion de uso de email en servicios publicos."),
                toolCapability("theharvester", "theHarvester", theHarvesterBinary, "cd /opt/theHarvester && uv run python -c 'import importlib.metadata as m; print(m.version(\"theharvester\"))'", "Recoleccion de emails, hosts y fuentes publicas por dominio.")
        ));
        response.put("platforms", PROFILE_SITES.keySet().stream().sorted().toList());
        response.put("defaults", Map.of(
                "platforms", List.of("linkedin", "github", "x", "instagram", "facebook", "tiktok"),
                "timeoutSeconds", 45,
                "topSites", 250,
                "domainSources", List.of("duckduckgo", "bing", "yahoo", "crtsh")
        ));
        return response;
    }

    public Map<String, Object> profileSearch(ProfileSearchRequest request, String username, String remoteIp) {
        String query = sanitizePersonQuery(request.query());
        List<String> platforms = sanitizePlatforms(request.platforms());
        int maxResults = clamp(value(request.maxResults(), 18), 3, 40);
        String locationHint = text(request.locationHint()).replaceAll("\\s+", " ");
        if (locationHint.length() > 80 || (hasText(locationHint) && !SAFE_PERSON.matcher(locationHint).matches())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Pista de ubicacion no valida");
        }

        auditEvents.save(new AuditEvent(username, "OSINT_PROFILE_SEARCH", query, remoteIp));

        List<Map<String, Object>> candidates = new ArrayList<>();
        List<Map<String, Object>> queries = new ArrayList<>();
        for (String platform : platforms) {
            String site = PROFILE_SITES.get(platform);
            String search = "\"" + query + "\" site:" + site;
            if (hasText(locationHint)) {
                search = search + " " + locationHint;
            }
            String searchUrl = "https://duckduckgo.com/html/?q=" + URLEncoder.encode(search, StandardCharsets.UTF_8);
            queries.add(Map.of("platform", platform, "query", search, "url", searchUrl));
            candidates.addAll(searchPublicProfiles(query, platform, site, search, Math.max(3, maxResults / Math.max(1, platforms.size()))));
        }

        candidates = deduplicateCandidates(candidates).stream()
                .sorted(Comparator.comparingInt(item -> -number(item.get("score"))))
                .limit(maxResults)
                .toList();

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("tool", "profile-search");
        response.put("query", query);
        response.put("platforms", platforms);
        response.put("generatedAt", Instant.now().toString());
        response.put("candidateCount", candidates.size());
        response.put("candidates", candidates);
        response.put("queries", queries);
        response.put("note", "Los resultados proceden de informacion publica indexada; valida manualmente antes de atribuir identidad.");
        return response;
    }

    public Map<String, Object> startSherlock(UsernameOsintRequest request, String username, String remoteIp) {
        requireCommand(sherlockBinary, "Sherlock");
        String target = sanitizeUsername(request.query());
        int timeout = clamp(value(request.timeoutSeconds(), 45), 5, 120);
        List<String> command = new ArrayList<>(List.of(
                sherlockBinary,
                target,
                "--print-found",
                "--no-color",
                "--timeout",
                String.valueOf(timeout)
        ));
        return startJob(username, remoteIp, "sherlock", target, storedParameters(request), command, timeout + 30, this::parseSocialProfileOutput);
    }

    public Map<String, Object> startMaigret(UsernameOsintRequest request, String username, String remoteIp) {
        requireCommand(maigretBinary, "Maigret");
        String target = sanitizeUsername(request.query());
        int timeout = clamp(value(request.timeoutSeconds(), 45), 5, 120);
        int topSites = clamp(value(request.topSites(), 250), 20, 1000);
        List<String> command = new ArrayList<>(List.of(
                maigretBinary,
                target,
                "--timeout",
                String.valueOf(timeout),
                "--top-sites",
                String.valueOf(topSites)
        ));
        if (!Boolean.TRUE.equals(request.deepMode())) {
            command.add("--no-progressbar");
        }
        return startJob(username, remoteIp, "maigret", target, storedParameters(request), command, Math.max(defaultTimeoutSeconds, timeout + 60), this::parseSocialProfileOutput);
    }

    public Map<String, Object> startSocialAnalyzer(UsernameOsintRequest request, String username, String remoteIp) {
        requireCommand(socialAnalyzerBinary, "Social Analyzer");
        String target = sanitizeLooseQuery(request.query());
        int topSites = clamp(value(request.topSites(), 100), 20, 500);
        int timeout = clamp(value(request.timeoutSeconds(), 45), 5, 120);
        List<String> command = new ArrayList<>(List.of(
                socialAnalyzerBinary,
                "--username",
                target,
                "--metadata",
                "--top",
                String.valueOf(topSites),
                "--timeout",
                String.valueOf(timeout)
        ));
        return startJob(username, remoteIp, "social-analyzer", target, storedParameters(request), command, timeout + 60, this::parseSocialProfileOutput);
    }

    public Map<String, Object> startHolehe(EmailOsintRequest request, String username, String remoteIp) {
        requireCommand(holeheBinary, "Holehe");
        String target = text(request.email()).toLowerCase(Locale.ROOT);
        int timeout = clamp(value(request.timeoutSeconds(), 45), 5, 120);
        List<String> command = new ArrayList<>(List.of(holeheBinary, target, "--no-color"));
        if (Boolean.TRUE.equals(request.onlyUsed())) {
            command.add("--only-used");
        }
        return startJob(username, remoteIp, "holehe", target, storedParameters(request), command, timeout + 30, this::parseHolehe);
    }

    public Map<String, Object> startTheHarvester(DomainOsintRequest request, String username, String remoteIp) {
        requireCommand(theHarvesterBinary, "theHarvester");
        String target = sanitizeDomain(request.domain());
        List<String> sources = sanitizeSources(request.sources());
        int limit = clamp(value(request.limit(), 200), 20, 1000);
        int timeout = clamp(value(request.timeoutSeconds(), 180), 10, 600);
        List<String> command = new ArrayList<>(List.of(
                theHarvesterBinary,
                "-d",
                target,
                "-b",
                String.join(",", sources),
                "-l",
                String.valueOf(limit)
        ));
        return startJob(username, remoteIp, "theharvester", target, storedParameters(request), command, timeout + 30, this::parseTheHarvester);
    }

    public Map<String, Object> job(UUID id, String username, String tool) {
        String normalizedTool = sanitizeJobTool(tool);
        ToolExecutionJob job = jobs.findById(id)
                .filter(item -> username.equals(item.getUsername()))
                .filter(item -> normalizedTool.equals(item.getTool()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Job OSINT no encontrado"));
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

    public List<Map<String, Object>> recentJobs(String tool, String username) {
        String normalizedTool = sanitizeJobTool(tool);
        return jobs.findByUsernameAndToolOrderByCreatedAtDesc(username, normalizedTool, PageRequest.of(0, 20)).stream()
                .map(job -> {
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
                })
                .toList();
    }

    private Map<String, Object> startJob(
            String username,
            String remoteIp,
            String tool,
            String target,
            Map<String, Object> parameters,
            List<String> command,
            long timeoutSeconds,
            ResultParser parser
    ) {
        ToolExecutionJob job = jobs.save(new ToolExecutionJob(username, tool, target, writeJson(parameters), preview(command)));
        RuntimeLog log = new RuntimeLog();
        runtimeLogs.put(job.getId(), log);
        auditEvents.save(new AuditEvent(username, "OSINT_" + tool.toUpperCase(Locale.ROOT).replace("-", "_") + "_START", target, remoteIp));
        CompletableFuture.runAsync(() -> runProcessJob(job.getId(), command, Math.min(defaultTimeoutSeconds, timeoutSeconds), log, parser), executor);
        return job(job.getId(), username, tool);
    }

    private void runProcessJob(UUID jobId, List<String> command, long timeoutSeconds, RuntimeLog log, ResultParser parser) {
        update(jobId, job -> job.markRunning("Preparando " + job.getTool()));
        Instant started = Instant.now();
        try {
            update(jobId, job -> job.updateProgress(8, "Lanzando proceso"));
            Process process = new ProcessBuilder(command).redirectErrorStream(false).start();
            update(jobId, job -> job.updateProgress(18, "Consulta OSINT en curso"));
            Future<String> stdout = executor.submit(readStream(process.getInputStream(), line -> log.add(line)));
            Future<String> stderr = executor.submit(readStream(process.getErrorStream(), line -> log.add(line)));
            boolean finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                throw new IllegalStateException("Tiempo maximo de ejecucion superado");
            }
            update(jobId, job -> job.updateProgress(86, "Normalizando resultados"));
            String out = stdout.get(3, TimeUnit.SECONDS);
            String err = stderr.get(3, TimeUnit.SECONDS);
            Map<String, Object> result = parser.parse(out, err, process.exitValue());
            result.put("durationMs", Duration.between(started, Instant.now()).toMillis());
            if (process.exitValue() == 0 || !asList(result.get("findings")).isEmpty()) {
                update(jobId, job -> job.markCompleted(writeJson(result)));
            } else {
                update(jobId, job -> job.markFailed("La herramienta termino sin resultados utiles", writeJson(result)));
            }
        } catch (Exception ex) {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("error", sample(ex.getMessage(), 900));
            result.put("logs", log.snapshot());
            update(jobId, job -> job.markFailed(ex.getMessage(), writeJson(result)));
        }
    }

    private List<Map<String, Object>> searchPublicProfiles(String person, String platform, String site, String query, int max) {
        try {
            URI uri = URI.create("https://duckduckgo.com/html/?q=" + URLEncoder.encode(query, StandardCharsets.UTF_8));
            HttpRequest request = HttpRequest.newBuilder(uri)
                    .timeout(Duration.ofSeconds(12))
                    .header("User-Agent", "Mozilla/5.0 CaligoOSINT/1.0")
                    .GET()
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() >= 400) {
                return List.of();
            }
            return parseSearchHtml(person, platform, site, response.body(), max);
        } catch (Exception ex) {
            return List.of();
        }
    }

    private List<Map<String, Object>> parseSearchHtml(String person, String platform, String site, String html, int max) {
        List<Map<String, Object>> results = new ArrayList<>();
        Pattern anchor = Pattern.compile("<a[^>]+class=\"result__a\"[^>]+href=\"([^\"]+)\"[^>]*>(.*?)</a>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
        Matcher matcher = anchor.matcher(html == null ? "" : html);
        while (matcher.find() && results.size() < max) {
            String url = resolveDuckDuckGoUrl(htmlDecode(matcher.group(1)));
            String title = cleanupHtml(matcher.group(2));
            if (!url.toLowerCase(Locale.ROOT).contains(site.toLowerCase(Locale.ROOT))) {
                continue;
            }
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("platform", platform);
            item.put("title", title);
            item.put("url", url);
            item.put("score", scoreCandidate(person, title, url, platform));
            item.put("source", "duckduckgo");
            results.add(item);
        }
        return results;
    }

    private Map<String, Object> parseSocialProfileOutput(String stdout, String stderr, int exitCode) {
        List<Map<String, Object>> findings = new ArrayList<>();
        LinkedHashSet<String> urls = extractUrls(stdout + "\n" + stderr);
        for (String url : urls) {
            Map<String, Object> finding = new LinkedHashMap<>();
            finding.put("platform", platformFromUrl(url));
            finding.put("url", url);
            finding.put("status", "found");
            finding.put("score", platformFromUrl(url).equals("unknown") ? 55 : 78);
            findings.add(finding);
        }
        if (findings.isEmpty()) {
            for (String line : (stdout + "\n" + stderr).split("\\R")) {
                String clean = stripAnsi(line).trim();
                if (!looksLikePositiveProfileLine(clean)) {
                    continue;
                }
                Map<String, Object> finding = new LinkedHashMap<>();
                finding.put("platform", inferPlatformFromLine(clean));
                finding.put("label", sample(clean, 300));
                finding.put("status", "found");
                finding.put("score", 60);
                findings.add(finding);
            }
        }
        Map<String, Object> result = baseResult(exitCode, stdout, stderr);
        result.put("findings", findings.stream().limit(240).toList());
        result.put("findingCount", findings.size());
        result.put("summary", summarizeProfiles(findings));
        return result;
    }

    private Map<String, Object> parseHolehe(String stdout, String stderr, int exitCode) {
        List<Map<String, Object>> findings = new ArrayList<>();
        for (String line : stdout.split("\\R")) {
            String clean = stripAnsi(line).trim();
            if (!looksLikeUsedEmailLine(clean)) {
                continue;
            }
            Map<String, Object> finding = new LinkedHashMap<>();
            finding.put("service", clean.replaceAll("^\\[[+xX\\-! ]+\\]\\s*", "").trim());
            finding.put("status", clean.startsWith("[+]") || clean.contains("+") ? "used" : "possible");
            finding.put("line", sample(clean, 400));
            findings.add(finding);
        }
        Map<String, Object> result = baseResult(exitCode, stdout, stderr);
        result.put("findings", findings);
        result.put("findingCount", findings.size());
        result.put("summary", Map.of("used", findings.size()));
        return result;
    }

    private Map<String, Object> parseTheHarvester(String stdout, String stderr, int exitCode) {
        String combined = stdout + "\n" + stderr;
        List<String> emails = EMAIL_PATTERN.matcher(combined).results()
                .map(MatchResult::group)
                .map(String::toLowerCase)
                .distinct()
                .limit(200)
                .toList();
        List<String> hosts = HOST_PATTERN.matcher(combined).results()
                .map(MatchResult::group)
                .map(String::toLowerCase)
                .filter(host -> !host.contains("@"))
                .distinct()
                .limit(300)
                .toList();
        List<String> urls = extractUrls(combined).stream().limit(200).toList();
        List<Map<String, Object>> findings = new ArrayList<>();
        emails.forEach(email -> findings.add(Map.of("type", "email", "value", email, "score", 80)));
        hosts.forEach(host -> findings.add(Map.of("type", "host", "value", host, "score", 70)));
        urls.forEach(url -> findings.add(Map.of("type", "url", "value", url, "score", 65)));
        Map<String, Object> result = baseResult(exitCode, stdout, stderr);
        result.put("emails", emails);
        result.put("hosts", hosts);
        result.put("urls", urls);
        result.put("findings", findings);
        result.put("findingCount", findings.size());
        result.put("summary", Map.of("emails", emails.size(), "hosts", hosts.size(), "urls", urls.size()));
        return result;
    }

    private Map<String, Object> baseResult(int exitCode, String stdout, String stderr) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("exitCode", exitCode);
        response.put("stdout", sample(stdout, 20000));
        response.put("stderr", sample(stderr, 12000));
        return response;
    }

    private Map<String, Object> summarizeProfiles(List<Map<String, Object>> findings) {
        Map<String, Integer> byPlatform = new LinkedHashMap<>();
        for (Map<String, Object> finding : findings) {
            String platform = value(finding.getOrDefault("platform", finding.get("service")));
            if (!hasText(platform)) {
                platform = "unknown";
            }
            byPlatform.put(platform, byPlatform.getOrDefault(platform, 0) + 1);
        }
        Map<String, Object> summary = new LinkedHashMap<>(byPlatform);
        summary.put("total", findings.size());
        return summary;
    }

    private Map<String, Object> toolCapability(String id, String label, String binary, String versionCommand, String description) {
        boolean available = commandAvailable(binary);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("id", id);
        response.put("label", label);
        response.put("binary", binary);
        response.put("available", available);
        response.put("version", available ? version(versionCommand) : "");
        response.put("description", description);
        return response;
    }

    private String version(String versionCommand) {
        ProcessResult result = runBlocking(List.of("sh", "-lc", versionCommand), 8);
        return firstNonBlank(result.output());
    }

    private ProcessResult runBlocking(List<String> command, long timeoutSeconds) {
        Instant started = Instant.now();
        try {
            Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
            Future<String> output = executor.submit(readStream(process.getInputStream(), line -> {
            }));
            boolean finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                return new ProcessResult(-1, output.get(2, TimeUnit.SECONDS), true, Duration.between(started, Instant.now()).toMillis());
            }
            return new ProcessResult(process.exitValue(), output.get(2, TimeUnit.SECONDS), false, Duration.between(started, Instant.now()).toMillis());
        } catch (Exception ex) {
            return new ProcessResult(127, sample(ex.getMessage(), 1000), false, Duration.between(started, Instant.now()).toMillis());
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

    private List<String> sanitizePlatforms(List<String> values) {
        if (values == null || values.isEmpty()) {
            return List.of("linkedin", "github", "x", "instagram", "facebook", "tiktok");
        }
        return values.stream()
                .map(OsintToolService::text)
                .map(value -> value.toLowerCase(Locale.ROOT))
                .filter(PROFILE_SITES::containsKey)
                .distinct()
                .limit(12)
                .toList();
    }

    private List<String> sanitizeSources(List<String> values) {
        if (values == null || values.isEmpty()) {
            return List.of("duckduckgo", "bing", "yahoo", "crtsh");
        }
        return values.stream()
                .map(OsintToolService::text)
                .filter(value -> SAFE_SOURCE.matcher(value).matches())
                .distinct()
                .limit(8)
                .toList();
    }

    private String sanitizePersonQuery(String value) {
        String query = text(value).replaceAll("\\s+", " ");
        if (!hasText(query) || !SAFE_PERSON.matcher(query).matches()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Nombre o consulta OSINT no valida");
        }
        return query;
    }

    private String sanitizeLooseQuery(String value) {
        String query = text(value).replaceAll("\\s+", " ");
        if (!hasText(query) || query.length() > 140 || !SAFE_PERSON.matcher(query).matches()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Consulta OSINT no valida");
        }
        return query;
    }

    private String sanitizeUsername(String value) {
        String username = text(value);
        if (!SAFE_USERNAME.matcher(username).matches()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username OSINT no valido");
        }
        return username;
    }

    private String sanitizeDomain(String value) {
        String domain = text(value).toLowerCase(Locale.ROOT).replaceFirst("^https?://", "").replaceFirst("/.*$", "");
        if (!SAFE_DOMAIN.matcher(domain).matches()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Dominio no valido");
        }
        return domain;
    }

    private String sanitizeJobTool(String tool) {
        String normalized = text(tool).toLowerCase(Locale.ROOT);
        if (!JOB_TOOLS.contains(normalized)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Herramienta OSINT no registrada");
        }
        return normalized;
    }

    private void requireCommand(String binary, String label) {
        if (!commandAvailable(binary)) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, label + " no esta instalado o no esta en PATH");
        }
    }

    private boolean commandAvailable(String binary) {
        try {
            Process process = new ProcessBuilder("sh", "-lc", "command -v " + binary).redirectErrorStream(true).start();
            return process.waitFor(5, TimeUnit.SECONDS) && process.exitValue() == 0;
        } catch (Exception ex) {
            return false;
        }
    }

    private LinkedHashSet<String> extractUrls(String text) {
        LinkedHashSet<String> urls = new LinkedHashSet<>();
        Matcher matcher = URL_PATTERN.matcher(stripAnsi(text == null ? "" : text));
        while (matcher.find()) {
            urls.add(matcher.group().replaceAll("[,.;]+$", ""));
        }
        return urls;
    }

    private List<Map<String, Object>> deduplicateCandidates(List<Map<String, Object>> candidates) {
        Map<String, Map<String, Object>> byUrl = new LinkedHashMap<>();
        for (Map<String, Object> candidate : candidates) {
            String url = value(candidate.get("url"));
            if (!hasText(url)) {
                continue;
            }
            byUrl.merge(url, candidate, (left, right) -> number(left.get("score")) >= number(right.get("score")) ? left : right);
        }
        return new ArrayList<>(byUrl.values());
    }

    private int scoreCandidate(String person, String title, String url, String platform) {
        String normalizedPerson = person.toLowerCase(Locale.ROOT);
        String haystack = (title + " " + url).toLowerCase(Locale.ROOT);
        int score = 45;
        for (String token : normalizedPerson.split("\\s+")) {
            if (token.length() > 2 && haystack.contains(token)) {
                score += 12;
            }
        }
        if ("linkedin".equals(platform)) {
            score += 12;
        }
        if (url.matches("(?i).*/in/[^/?#]+.*|.*/user/[^/?#]+.*|.*github\\.com/[^/?#]+.*")) {
            score += 8;
        }
        return Math.min(100, score);
    }

    private String resolveDuckDuckGoUrl(String value) {
        if (value == null) {
            return "";
        }
        String url = value;
        int index = url.indexOf("uddg=");
        if (index >= 0) {
            String encoded = url.substring(index + 5).split("&", 2)[0];
            return URLDecoder.decode(encoded, StandardCharsets.UTF_8);
        }
        return url;
    }

    private String platformFromUrl(String url) {
        String lower = url.toLowerCase(Locale.ROOT);
        return PROFILE_SITES.entrySet().stream()
                .filter(entry -> lower.contains(entry.getValue()))
                .map(Map.Entry::getKey)
                .findFirst()
                .orElse("unknown");
    }

    private String inferPlatformFromLine(String line) {
        String lower = line.toLowerCase(Locale.ROOT);
        return PROFILE_SITES.keySet().stream()
                .filter(lower::contains)
                .findFirst()
                .orElse("unknown");
    }

    private boolean looksLikePositiveProfileLine(String line) {
        String lower = line.toLowerCase(Locale.ROOT);
        return hasText(line)
                && (lower.contains("[+]") || lower.contains("found") || lower.contains("exists"))
                && !lower.contains("not found")
                && !lower.contains("error");
    }

    private boolean looksLikeUsedEmailLine(String line) {
        String lower = line.toLowerCase(Locale.ROOT);
        return hasText(line)
                && (line.startsWith("[+]") || lower.contains("used") || lower.contains("exists"))
                && !lower.contains("not found")
                && !lower.contains("rate limit");
    }

    private void update(UUID jobId, java.util.function.Consumer<ToolExecutionJob> mutation) {
        jobs.findById(jobId).ifPresent(job -> {
            mutation.accept(job);
            jobs.save(job);
        });
    }

    private Map<String, Object> storedParameters(Object request) {
        return objectMapper.convertValue(request, new TypeReference<>() {
        });
    }

    private Map<String, Object> readJson(String json) {
        if (!hasText(json)) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(json, new TypeReference<>() {
            });
        } catch (JsonProcessingException ex) {
            return Map.of("raw", json);
        }
    }

    private String writeJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value == null ? Map.of() : value);
        } catch (JsonProcessingException ex) {
            return "{}";
        }
    }

    private List<?> asList(Object value) {
        return value instanceof List<?> list ? list : List.of();
    }

    private int number(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        try {
            return Integer.parseInt(String.valueOf(value));
        } catch (Exception ex) {
            return 0;
        }
    }

    private int value(Integer value, int fallback) {
        return value == null ? fallback : value;
    }

    private int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }

    private String string(Instant instant) {
        return instant == null ? "" : instant.toString();
    }

    private long durationMs(Instant start, Instant end) {
        if (start == null) {
            return 0;
        }
        return Duration.between(start, end == null ? Instant.now() : end).toMillis();
    }

    private static String firstNonBlank(String value) {
        if (value == null) {
            return "";
        }
        return value.lines()
                .map(String::trim)
                .filter(line -> !line.isBlank())
                .findFirst()
                .orElse("");
    }

    private static String cleanupHtml(String value) {
        return htmlDecode(value == null ? "" : value.replaceAll("<[^>]+>", " ").replaceAll("\\s+", " ").trim());
    }

    private static String htmlDecode(String value) {
        return String.valueOf(value)
                .replace("&amp;", "&")
                .replace("&quot;", "\"")
                .replace("&#x27;", "'")
                .replace("&#39;", "'")
                .replace("&lt;", "<")
                .replace("&gt;", ">");
    }

    private static String stripAnsi(String value) {
        return value == null ? "" : value.replaceAll("\\u001B\\[[;\\d]*m", "");
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private static String text(String value) {
        return value == null ? "" : value.trim();
    }

    private static String value(Object value) {
        return value == null ? "" : String.valueOf(value);
    }

    private static String sample(String value, int maxChars) {
        if (value == null) {
            return "";
        }
        String cleaned = stripAnsi(value);
        if (cleaned.length() <= maxChars) {
            return cleaned;
        }
        return cleaned.substring(0, Math.max(0, maxChars - 18)) + "\n[...truncado...]";
    }

    private static String preview(List<String> command) {
        return String.join(" ", command);
    }

    @FunctionalInterface
    private interface ResultParser {
        Map<String, Object> parse(String stdout, String stderr, int exitCode);
    }

    private record ProcessResult(int exitCode, String output, boolean timedOut, long durationMs) {
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
            lines.add(sample(line, 500));
        }

        synchronized List<String> snapshot() {
            return List.copyOf(lines);
        }
    }
}
