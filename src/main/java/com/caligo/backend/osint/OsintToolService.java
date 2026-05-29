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
import java.nio.file.Files;
import java.nio.file.Path;
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
import java.util.stream.Stream;

@Service
public class OsintToolService {

    private static final Pattern SAFE_PERSON = Pattern.compile("(?U)^[\\p{L}\\p{N}][\\p{L}\\p{N} .,'_\\-]{1,139}$");
    private static final Pattern SAFE_USERNAME = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._\\-]{1,63}$");
    private static final Pattern SAFE_DOMAIN = Pattern.compile("(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,30}$");
    private static final Pattern SAFE_HOST = Pattern.compile("(?i)^(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,30}|(?:\\d{1,3}\\.){3}\\d{1,3})$");
    private static final Pattern SAFE_SOURCE = Pattern.compile("^[a-zA-Z0-9_-]{2,40}$");
    private static final Pattern SAFE_HEADER = Pattern.compile("^[A-Za-z0-9-]{2,48}:\\s?[^\\r\\n]{1,130}$");
    private static final Pattern SAFE_BRANCH = Pattern.compile("^[A-Za-z0-9._/\\-]{1,90}$");
    private static final Pattern SAFE_MODULE = Pattern.compile("^[A-Za-z0-9_.-]{2,80}$");
    private static final Pattern SAFE_EVENT_TYPE = Pattern.compile("^[A-Z0-9_]{2,80}$");
    private static final Pattern SAFE_PATH_FILTER = Pattern.compile("^[A-Za-z0-9._~!$&'()*+,;=:@%/\\\\\\-]{1,180}$");
    private static final Pattern EMAIL_PATTERN = Pattern.compile("[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,24}");
    private static final Pattern URL_PATTERN = Pattern.compile("https?://[^\\s\"'<>\\])}]+", Pattern.CASE_INSENSITIVE);
    private static final Pattern HOST_PATTERN = Pattern.compile("(?i)\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,30}\\b");
    private static final Set<String> JOB_TOOLS = Set.of("sherlock", "maigret", "social-analyzer", "holehe", "theharvester", "git-dumper", "spiderfoot", "trufflehog");
    private static final Set<String> SPIDERFOOT_PROFILES = Set.of("passive", "footprint", "investigate", "all", "custom");
    private static final Set<String> SPIDERFOOT_TARGET_TYPES = Set.of("auto", "domain", "ip", "netblock", "email", "username", "name", "phone");
    private static final Map<String, List<String>> SPIDERFOOT_MODULE_PRESETS = Map.of(
            "passive", List.of("sfp_dnsresolve", "sfp_whois", "sfp_crtsh", "sfp_arin", "sfp_bingsearch"),
            "footprint", List.of("sfp_dnsresolve", "sfp_whois", "sfp_crtsh", "sfp_dnsbrute", "sfp_bingsearch", "sfp_social"),
            "investigate", List.of("sfp_dnsresolve", "sfp_whois", "sfp_crtsh", "sfp_email", "sfp_pgp", "sfp_social")
    );
    private static final Map<String, String> SPIDERFOOT_EVENT_PRESETS = Map.of(
            "domain", "DOMAIN_NAME",
            "ip", "IP_ADDRESS",
            "netblock", "NETBLOCK_OWNER",
            "email", "EMAILADDR",
            "username", "USERNAME",
            "name", "HUMAN_NAME",
            "phone", "PHONE_NUMBER"
    );
    private static final Set<String> TRUFFLEHOG_SOURCE_TYPES = Set.of("git", "github", "filesystem");
    private static final Set<String> TRUFFLEHOG_RESULTS = Set.of("verified", "unknown", "unverified", "verified,unknown", "verified,unknown,unverified", "all");
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
    private final String gitDumperBinary;
    private final String spiderFootBinary;
    private final String truffleHogBinary;
    private final Path gitDumperOutputRoot;
    private final Path osintTempRoot;
    private final List<Path> truffleHogAllowedRoots;
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
            @Value("${caligo.osint.git-dumper.binary:git-dumper}") String gitDumperBinary,
            @Value("${caligo.osint.git-dumper.output-dir:/tmp/caligo/git-dumper}") String gitDumperOutputRoot,
            @Value("${caligo.osint.spiderfoot.binary:spiderfoot}") String spiderFootBinary,
            @Value("${caligo.osint.trufflehog.binary:trufflehog}") String truffleHogBinary,
            @Value("${caligo.osint.trufflehog.allowed-roots:/tmp/caligo/git-dumper,/var/www/caligo,/opt/caligo}") String truffleHogAllowedRoots,
            @Value("${caligo.osint.temp-dir:/tmp/caligo/osint}") String osintTempRoot,
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
        this.gitDumperBinary = gitDumperBinary;
        this.spiderFootBinary = spiderFootBinary;
        this.truffleHogBinary = truffleHogBinary;
        this.gitDumperOutputRoot = Path.of(gitDumperOutputRoot).toAbsolutePath().normalize();
        this.osintTempRoot = Path.of(osintTempRoot).toAbsolutePath().normalize();
        this.truffleHogAllowedRoots = Stream.of(truffleHogAllowedRoots.split(","))
                .map(String::trim)
                .filter(OsintToolService::hasText)
                .map(value -> Path.of(value).toAbsolutePath().normalize())
                .toList();
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
                toolCapability("theharvester", "theHarvester", theHarvesterBinary, "cd /opt/theHarvester && uv run python -c 'import importlib.metadata as m; print(m.version(\"theharvester\"))'", "Recoleccion de emails, hosts y fuentes publicas por dominio."),
                toolCapability("git-dumper", "git-dumper", gitDumperBinary, "git-dumper --help | head -n 1", "Recuperacion controlada de repositorios .git expuestos."),
                toolCapability("spiderfoot", "SpiderFoot", spiderFootBinary, "spiderfoot --version 2>/dev/null || spiderfoot -h | head -n 1", "Correlacion OSINT multi-fuente con perfiles y modulos configurables."),
                toolCapability("trufflehog", "TruffleHog", truffleHogBinary, "trufflehog --version", "Deteccion de secretos en repositorios, directorios y artefactos autorizados."),
                Map.of("id", "email-exposure", "label", "Email Exposure", "binary", "backend-http", "available", true, "version", "server-side", "description", "Analisis seguro de email, dominio, MX y patrones profesionales."),
                Map.of("id", "phone-lookup", "label", "Phone Lookup", "binary", "backend-http", "available", true, "version", "server-side", "description", "Normalizacion y validacion del telefono aportado por el usuario."),
                Map.of("id", "domain-contacts", "label", "Domain Contacts", "binary", "backend-http", "available", true, "version", "server-side", "description", "Extraccion de contactos publicados por dominios autorizados."),
                Map.of("id", "password-exposure", "label", "Password Exposure Check", "binary", "Pwned Passwords", "available", true, "version", "k-anonymity", "description", "Comprobacion k-anon de passwords sin enviar el secreto completo."),
                Map.of("id", "metadata-exposure", "label", "Metadata Exposure", "binary", "backend-http", "available", true, "version", "server-side", "description", "Cabeceras y metadatos visibles de documentos publicos."),
                Map.of("id", "public-files", "label", "Public Files", "binary", "backend-http", "available", true, "version", "server-side", "description", "Inventario de ficheros publicos habituales del dominio.")
        ));
        response.put("platforms", PROFILE_SITES.keySet().stream().sorted().toList());
        response.put("defaults", Map.of(
                "platforms", List.of("linkedin", "github", "x", "instagram", "facebook", "tiktok"),
                "timeoutSeconds", 45,
                "topSites", 250,
                "domainSources", List.of("duckduckgo", "bing", "yahoo", "crtsh"),
                "spiderFootProfiles", SPIDERFOOT_PROFILES.stream().sorted().toList(),
                "spiderFootModules", SPIDERFOOT_MODULE_PRESETS,
                "truffleHogSourceTypes", TRUFFLEHOG_SOURCE_TYPES.stream().sorted().toList(),
                "truffleHogResults", TRUFFLEHOG_RESULTS.stream().sorted().toList()
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
                "--no-txt",
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

    public Map<String, Object> startGitDumper(GitDumperRequest request, String username, String remoteIp) {
        requireAuthorized(request.authorized());
        requireCommand(gitDumperBinary, "git-dumper");
        URI targetUri = sanitizeGitDumperUrl(request.url(), Boolean.TRUE.equals(request.appendGitPath()));
        int jobsCount = clamp(value(request.jobs(), 10), 1, 40);
        int retryCount = clamp(value(request.retry(), 3), 0, 10);
        int cliTimeout = clamp(value(request.timeoutSeconds(), 120), 5, 900);
        List<String> headers = sanitizeHeaders(request.headers());
        List<String> branches = sanitizeBranches(request.branches());
        String proxy = sanitizeProxy(request.proxy());
        String userAgent = sanitizeUserAgent(request.userAgent());
        Path outputDir = gitDumperOutputDirectory(username);

        List<String> command = new ArrayList<>(List.of(
                gitDumperBinary,
                "--jobs",
                String.valueOf(jobsCount),
                "--retry",
                String.valueOf(retryCount),
                "--timeout",
                String.valueOf(cliTimeout)
        ));
        if (hasText(userAgent)) {
            command.add("--user-agent");
            command.add(userAgent);
        }
        if (hasText(proxy)) {
            command.add("--proxy");
            command.add(proxy);
        }
        for (String header : headers) {
            command.add("--header");
            command.add(header);
        }
        for (String branch : branches) {
            command.add("--branch");
            command.add(branch);
        }
        command.add(targetUri.toString());
        command.add(outputDir.toString());

        Map<String, Object> parameters = storedParameters(request);
        parameters.put("normalizedUrl", targetUri.toString());
        parameters.put("outputDir", outputDir.toString());
        return startJob(username, remoteIp, "git-dumper", targetUri.toString(), parameters, command, cliTimeout + 120, (stdout, stderr, exitCode) -> parseGitDumper(stdout, stderr, exitCode, outputDir));
    }

    public Map<String, Object> startSpiderFoot(SpiderFootRequest request, String username, String remoteIp) {
        requireAuthorized(request.authorized(), "Confirma alcance autorizado antes de ejecutar SpiderFoot.");
        requireCommand(spiderFootBinary, "SpiderFoot");
        String target = sanitizeSpiderFootTarget(request.target(), request.targetType());
        String targetType = sanitizeSpiderFootTargetType(request.targetType(), target);
        String profile = sanitizeSpiderFootProfile(request.scanProfile());
        List<String> modules = sanitizeSpiderFootModules(request.modules(), profile);
        List<String> eventTypes = sanitizeSpiderFootEventTypes(request.eventTypes(), targetType);
        int timeout = clamp(value(request.timeoutSeconds(), 900), 60, 3600);

        List<String> command = new ArrayList<>(List.of(
                spiderFootBinary,
                "-s",
                target,
                "-q",
                "-o",
                "json"
        ));
        if (!eventTypes.isEmpty()) {
            command.add("-t");
            command.add(String.join(",", eventTypes));
        }
        if (!modules.isEmpty()) {
            command.add("-m");
            command.add(String.join(",", modules));
        } else if (!"custom".equals(profile)) {
            command.add("-u");
            command.add(profile);
        }
        if (Boolean.TRUE.equals(request.strictMode())) {
            command.add("-x");
        }

        Map<String, Object> parameters = storedParameters(request);
        parameters.put("normalizedTarget", target);
        parameters.put("targetType", targetType);
        parameters.put("modules", modules);
        parameters.put("eventTypes", eventTypes);
        auditEvents.save(new AuditEvent(username, "OSINT_SPIDERFOOT_START", target, remoteIp));
        return startJob(username, remoteIp, "spiderfoot", target, parameters, command, timeout + 60, this::parseSpiderFoot);
    }

    public Map<String, Object> startTruffleHog(TruffleHogRequest request, String username, String remoteIp) {
        requireAuthorized(request.authorized(), "Confirma alcance autorizado antes de ejecutar TruffleHog.");
        requireCommand(truffleHogBinary, "TruffleHog");
        String sourceType = sanitizeTruffleHogSourceType(request.sourceType());
        String target = sanitizeTruffleHogTarget(sourceType, request.target());
        String results = sanitizeTruffleHogResults(request.results());
        int timeout = clamp(value(request.timeoutSeconds(), 900), 30, 3600);
        int concurrency = clamp(value(request.concurrency(), 8), 1, 64);

        List<String> command = new ArrayList<>(List.of(
                truffleHogBinary,
                sourceType
        ));
        if ("github".equals(sourceType)) {
            command.add("--repo");
            command.add(target);
        } else {
            command.add(target);
        }
        command.add("--json");
        command.add("--no-update");
        command.add("--concurrency");
        command.add(String.valueOf(concurrency));
        command.add("--results=" + results);
        if (Boolean.TRUE.equals(request.noVerification())) {
            command.add("--no-verification");
        }
        if (Boolean.TRUE.equals(request.filterEntropy())) {
            command.add("--filter-entropy=3.0");
        }
        if (Boolean.TRUE.equals(request.scanEntireChunk())) {
            command.add("--scan-entire-chunk");
        }
        if (Set.of("git", "github").contains(sourceType)) {
            String branch = sanitizeBranch(request.branch());
            if (hasText(branch)) {
                command.add("--branch");
                command.add(branch);
            }
            Integer maxDepth = request.maxDepth();
            if (maxDepth != null) {
                command.add("--max-depth");
                command.add(String.valueOf(clamp(maxDepth, 1, 5000)));
            }
        }
        addPathFilterFile(command, "--include-paths", request.includePaths(), username, "include");
        addPathFilterFile(command, "--exclude-paths", request.excludePaths(), username, "exclude");

        Map<String, Object> parameters = storedParameters(request);
        parameters.put("sourceType", sourceType);
        parameters.put("normalizedTarget", target);
        parameters.put("results", results);
        return startJob(username, remoteIp, "trufflehog", target, parameters, command, timeout + 60, this::parseTruffleHog);
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

    private Map<String, Object> parseGitDumper(String stdout, String stderr, int exitCode, Path outputDir) {
        List<Map<String, Object>> files = new ArrayList<>();
        long totalBytes = 0;
        try (Stream<Path> paths = Files.exists(outputDir) ? Files.walk(outputDir) : Stream.empty()) {
            List<Path> regularFiles = paths
                    .filter(Files::isRegularFile)
                    .sorted()
                    .toList();
            for (Path file : regularFiles) {
                long size = safeFileSize(file);
                totalBytes += size;
                if (files.size() < 120) {
                    String relative = outputDir.relativize(file).toString().replace('\\', '/');
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("path", relative);
                    row.put("size", size);
                    row.put("category", classifyGitDumpFile(relative));
                    files.add(row);
                }
            }
        } catch (IOException ignored) {
            // La salida parcial del CLI sigue siendo util aunque falle el inventario de ficheros.
        }

        boolean repositoryRecovered = files.stream()
                .map(item -> value(item.get("path")))
                .anyMatch(path -> path.startsWith(".git/") || path.equals(".git"));
        List<Map<String, Object>> findings = new ArrayList<>();
        if (repositoryRecovered || !files.isEmpty()) {
            findings.add(Map.of("type", "repository", "value", "artefactos recuperados", "score", 78));
        }
        files.stream()
                .filter(item -> Set.of("git-metadata", "source", "config").contains(value(item.get("category"))))
                .limit(12)
                .forEach(item -> findings.add(Map.of(
                        "type", item.get("category"),
                        "value", item.get("path"),
                        "score", "config".equals(item.get("category")) ? 86 : 68
                )));

        Map<String, Object> result = baseResult(exitCode, stdout, stderr);
        result.put("outputDir", outputDir.toString());
        result.put("fileCount", files.size());
        result.put("totalBytes", totalBytes);
        result.put("repositoryRecovered", repositoryRecovered);
        result.put("files", files);
        result.put("findings", findings);
        result.put("findingCount", findings.size());
        result.put("summary", Map.of(
                "files", files.size(),
                "bytes", totalBytes,
                "repositoryRecovered", repositoryRecovered,
                "outputDir", outputDir.toString()
        ));
        return result;
    }

    private Map<String, Object> parseSpiderFoot(String stdout, String stderr, int exitCode) {
        String combined = stdout + "\n" + stderr;
        List<Map<String, Object>> findings = new ArrayList<>();
        Object parsed = readArbitraryJson(stdout);
        if (parsed instanceof List<?> list) {
            for (Object item : list) {
                if (item instanceof Map<?, ?> map) {
                    findings.add(spiderFootFinding(map));
                }
            }
        } else if (parsed instanceof Map<?, ?> map) {
            Object data = map.get("data");
            if (data instanceof List<?> list) {
                for (Object item : list) {
                    if (item instanceof Map<?, ?> row) {
                        findings.add(spiderFootFinding(row));
                    }
                }
            } else {
                findings.add(spiderFootFinding(map));
            }
        }
        if (findings.isEmpty()) {
            for (String line : combined.split("\\R")) {
                String clean = stripAnsi(line).trim();
                if (!hasText(clean) || clean.startsWith("[") || clean.length() < 8) {
                    continue;
                }
                findings.add(Map.of("type", "line", "value", sample(clean, 280), "module", "spiderfoot", "score", 48));
                if (findings.size() >= 180) {
                    break;
                }
            }
        }
        Map<String, Integer> byType = new LinkedHashMap<>();
        for (Map<String, Object> finding : findings) {
            String type = value(finding.get("type"));
            byType.put(type, byType.getOrDefault(type, 0) + 1);
        }
        Map<String, Object> result = baseResult(exitCode, stdout, stderr);
        result.put("findings", findings.stream().limit(500).toList());
        result.put("findingCount", findings.size());
        result.put("summary", Map.of(
                "total", findings.size(),
                "types", byType,
                "urls", findings.stream().filter(item -> hasText(value(item.get("url")))).count()
        ));
        return result;
    }

    private Map<String, Object> parseTruffleHog(String stdout, String stderr, int exitCode) {
        List<Map<String, Object>> findings = new ArrayList<>();
        int verified = 0;
        int unknown = 0;
        int unverified = 0;
        for (String line : stdout.split("\\R")) {
            String clean = line.trim();
            if (!clean.startsWith("{")) {
                continue;
            }
            Object parsed = readArbitraryJson(clean);
            if (!(parsed instanceof Map<?, ?> map)) {
                continue;
            }
            Map<String, Object> finding = truffleHogFinding(map);
            String status = value(finding.get("status"));
            if ("verified".equals(status)) {
                verified++;
            } else if ("unknown".equals(status)) {
                unknown++;
            } else {
                unverified++;
            }
            findings.add(finding);
        }
        Map<String, Object> result = baseResult(exitCode, stdout, stderr);
        result.put("findings", findings.stream().limit(500).toList());
        result.put("findingCount", findings.size());
        result.put("summary", Map.of(
                "total", findings.size(),
                "verified", verified,
                "unknown", unknown,
                "unverified", unverified
        ));
        return result;
    }

    private Map<String, Object> spiderFootFinding(Map<?, ?> map) {
        String type = firstValue(map, "type", "eventType", "event_type", "event");
        String value = firstValue(map, "data", "value", "content", "name");
        String module = firstValue(map, "module", "source", "provider");
        String url = firstValue(map, "url", "sourceUrl", "source_url");
        String confidence = firstValue(map, "confidence", "risk", "severity");
        Map<String, Object> finding = new LinkedHashMap<>();
        finding.put("type", hasText(type) ? type : "spiderfoot");
        finding.put("value", sample(hasText(value) ? value : map.toString(), 500));
        finding.put("module", hasText(module) ? module : "spiderfoot");
        finding.put("url", url);
        finding.put("confidence", confidence);
        finding.put("score", scoreSpiderFoot(type, confidence));
        return finding;
    }

    private Map<String, Object> truffleHogFinding(Map<?, ?> map) {
        String detector = firstValue(map, "DetectorName", "detectorName", "detector_name");
        String raw = firstValue(map, "Raw", "raw", "Redacted", "redacted");
        String verifiedValue = firstValue(map, "Verified", "verified");
        boolean verified = Boolean.parseBoolean(verifiedValue);
        String sourceType = firstValue(map, "SourceType", "source_type", "sourceType");
        String sourceName = firstValue(map, "SourceName", "source_name", "sourceName");
        String sourceId = firstValue(map, "SourceID", "source_id", "sourceId");
        String status = verified ? "verified" : "unknown";
        Map<String, Object> finding = new LinkedHashMap<>();
        finding.put("type", hasText(detector) ? detector : "secret");
        finding.put("value", sample(redactSecret(raw), 220));
        finding.put("status", status);
        finding.put("sourceType", sourceType);
        finding.put("source", firstNonBlank(sourceName + " " + sourceId));
        finding.put("score", verified ? 95 : 72);
        finding.put("metadata", map);
        return finding;
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

    private String sanitizeSpiderFootProfile(String value) {
        String profile = text(value).toLowerCase(Locale.ROOT);
        if (!hasText(profile)) {
            return "passive";
        }
        if (!SPIDERFOOT_PROFILES.contains(profile)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Perfil SpiderFoot no valido");
        }
        return profile;
    }

    private String sanitizeSpiderFootTargetType(String value, String target) {
        String type = text(value).toLowerCase(Locale.ROOT);
        if (!hasText(type) || "auto".equals(type)) {
            if (EMAIL_PATTERN.matcher(target).matches()) return "email";
            if (target.matches("^(?:\\d{1,3}\\.){3}\\d{1,3}$")) return "ip";
            if (SAFE_DOMAIN.matcher(target).matches()) return "domain";
            return "name";
        }
        if (!SPIDERFOOT_TARGET_TYPES.contains(type)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Tipo de objetivo SpiderFoot no valido");
        }
        return type;
    }

    private String sanitizeSpiderFootTarget(String value, String targetType) {
        String target = text(value).replaceAll("\\s+", " ");
        String type = text(targetType).toLowerCase(Locale.ROOT);
        if (!hasText(target) || target.length() > 180) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Objetivo SpiderFoot no valido");
        }
        if ("domain".equals(type)) {
            return sanitizeDomain(target);
        }
        if ("email".equals(type) && !EMAIL_PATTERN.matcher(target).matches()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email SpiderFoot no valido");
        }
        if ("ip".equals(type) && (!target.matches("^(?:\\d{1,3}\\.){3}\\d{1,3}$") || isInvalidIpv4Literal(target))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "IP SpiderFoot no valida");
        }
        if (target.matches(".*[\\r\\n;`$<>].*")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Objetivo SpiderFoot no valido");
        }
        return target;
    }

    private List<String> sanitizeSpiderFootModules(List<String> values, String profile) {
        List<String> modules = values == null ? List.of() : values.stream()
                .map(OsintToolService::text)
                .filter(SAFE_MODULE.asMatchPredicate())
                .distinct()
                .limit(24)
                .toList();
        if (!modules.isEmpty() || "custom".equals(profile) || "all".equals(profile)) {
            return modules;
        }
        return SPIDERFOOT_MODULE_PRESETS.getOrDefault(profile, List.of());
    }

    private List<String> sanitizeSpiderFootEventTypes(List<String> values, String targetType) {
        List<String> events = values == null ? List.of() : values.stream()
                .map(OsintToolService::text)
                .map(value -> value.toUpperCase(Locale.ROOT))
                .filter(SAFE_EVENT_TYPE.asMatchPredicate())
                .distinct()
                .limit(20)
                .toList();
        if (!events.isEmpty()) {
            return events;
        }
        String event = SPIDERFOOT_EVENT_PRESETS.get(targetType);
        return hasText(event) ? List.of(event) : List.of();
    }

    private String sanitizeTruffleHogSourceType(String value) {
        String sourceType = text(value).toLowerCase(Locale.ROOT);
        if (!TRUFFLEHOG_SOURCE_TYPES.contains(sourceType)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Tipo de fuente TruffleHog no valido");
        }
        return sourceType;
    }

    private String sanitizeTruffleHogResults(String value) {
        String results = text(value).toLowerCase(Locale.ROOT);
        if (!hasText(results)) {
            return "verified,unknown";
        }
        if ("all".equals(results)) {
            return "verified,unknown,unverified";
        }
        if (!TRUFFLEHOG_RESULTS.contains(results)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Filtro de resultados TruffleHog no valido");
        }
        return results;
    }

    private String sanitizeTruffleHogTarget(String sourceType, String value) {
        String target = text(value);
        if ("filesystem".equals(sourceType)) {
            return sanitizeAllowedLocalPath(target).toString();
        }
        if (target.startsWith("file://")) {
            return "file://" + sanitizeAllowedLocalPath(target.substring("file://".length()));
        }
        URI uri = normalizeHttpUrl(target, "Destino TruffleHog no valido");
        return uri.toString();
    }

    private Path sanitizeAllowedLocalPath(String value) {
        try {
            Path path = Path.of(value).toAbsolutePath().normalize();
            boolean allowed = truffleHogAllowedRoots.stream().anyMatch(path::startsWith);
            if (!allowed) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Ruta fuera de los directorios permitidos para TruffleHog");
            }
            return path;
        } catch (ResponseStatusException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Ruta TruffleHog no valida");
        }
    }

    private URI normalizeHttpUrl(String value, String errorMessage) {
        String raw = text(value);
        if (!raw.startsWith("http://") && !raw.startsWith("https://")) {
            raw = "https://" + raw;
        }
        try {
            URI uri = URI.create(raw);
            String scheme = text(uri.getScheme()).toLowerCase(Locale.ROOT);
            String host = text(uri.getHost()).toLowerCase(Locale.ROOT);
            if (!Set.of("http", "https").contains(scheme) || hasText(uri.getUserInfo()) || !SAFE_HOST.matcher(host).matches() || isInvalidIpv4Literal(host)) {
                throw new IllegalArgumentException("url");
            }
            return uri;
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, errorMessage);
        }
    }

    private String sanitizeBranch(String value) {
        String branch = text(value);
        if (!hasText(branch)) {
            return "";
        }
        if (!SAFE_BRANCH.matcher(branch).matches() || branch.contains("..")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Rama no valida");
        }
        return branch;
    }

    private void addPathFilterFile(List<String> command, String option, List<String> values, String username, String prefix) {
        List<String> filters = sanitizePathFilters(values);
        if (filters.isEmpty()) {
            return;
        }
        Path file = osintTempFile(username, prefix + "-paths", ".txt");
        try {
            Files.writeString(file, String.join("\n", filters), StandardCharsets.UTF_8);
        } catch (IOException ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "No se pudo preparar filtro de rutas");
        }
        command.add(option);
        command.add(file.toString());
    }

    private List<String> sanitizePathFilters(List<String> values) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        return values.stream()
                .map(OsintToolService::text)
                .filter(SAFE_PATH_FILTER.asMatchPredicate())
                .filter(value -> !value.contains(".."))
                .distinct()
                .limit(16)
                .toList();
    }

    private Path osintTempFile(String username, String prefix, String suffix) {
        String safeUser = text(username).replaceAll("[^A-Za-z0-9._-]", "_");
        Path userDir = osintTempRoot.resolve(safeUser).normalize();
        if (!userDir.startsWith(osintTempRoot)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Directorio temporal no valido");
        }
        try {
            Files.createDirectories(userDir);
            return Files.createTempFile(userDir, prefix + "-", suffix);
        } catch (IOException ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "No se pudo preparar directorio temporal OSINT");
        }
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

    private URI sanitizeGitDumperUrl(String value, boolean appendGitPath) {
        String raw = text(value);
        if (!raw.startsWith("http://") && !raw.startsWith("https://")) {
            raw = "https://" + raw;
        }
        try {
            URI uri = URI.create(raw);
            String scheme = text(uri.getScheme()).toLowerCase(Locale.ROOT);
            if (!Set.of("http", "https").contains(scheme) || hasText(uri.getUserInfo())) {
                throw new IllegalArgumentException("scheme");
            }
            String host = text(uri.getHost()).toLowerCase(Locale.ROOT);
            if (!SAFE_HOST.matcher(host).matches() || isInvalidIpv4Literal(host)) {
                throw new IllegalArgumentException("host");
            }
            String path = hasText(uri.getRawPath()) ? uri.getRawPath() : "/";
            if (appendGitPath && !path.toLowerCase(Locale.ROOT).contains("/.git")) {
                path = path.replaceAll("/+$", "") + "/.git/";
            }
            String query = hasText(uri.getRawQuery()) ? "?" + uri.getRawQuery() : "";
            return URI.create(scheme + "://" + host + path + query);
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "URL de repositorio .git no valida");
        }
    }

    private List<String> sanitizeHeaders(List<String> values) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        return values.stream()
                .map(OsintToolService::text)
                .filter(SAFE_HEADER.asMatchPredicate())
                .filter(header -> {
                    String name = header.split(":", 2)[0].toLowerCase(Locale.ROOT);
                    return !Set.of("authorization", "cookie", "proxy-authorization").contains(name);
                })
                .distinct()
                .limit(8)
                .toList();
    }

    private List<String> sanitizeBranches(List<String> values) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        return values.stream()
                .map(OsintToolService::text)
                .filter(branch -> SAFE_BRANCH.matcher(branch).matches())
                .filter(branch -> !branch.contains(".."))
                .distinct()
                .limit(8)
                .toList();
    }

    private String sanitizeUserAgent(String value) {
        String userAgent = text(value);
        if (!hasText(userAgent)) {
            return "";
        }
        if (userAgent.length() > 180 || userAgent.matches(".*[\\r\\n].*")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User-Agent no valido");
        }
        return userAgent;
    }

    private String sanitizeProxy(String value) {
        String proxy = text(value);
        if (!hasText(proxy)) {
            return "";
        }
        try {
            URI uri = URI.create(proxy);
            String scheme = text(uri.getScheme()).toLowerCase(Locale.ROOT);
            if (!Set.of("http", "https", "socks4", "socks5").contains(scheme) || hasText(uri.getUserInfo())) {
                throw new IllegalArgumentException("proxy");
            }
            String host = text(uri.getHost()).toLowerCase(Locale.ROOT);
            int port = uri.getPort();
            if (!SAFE_HOST.matcher(host).matches() || port < 1 || port > 65535 || isInvalidIpv4Literal(host)) {
                throw new IllegalArgumentException("proxy");
            }
            return proxy;
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Proxy no valido");
        }
    }

    private Path gitDumperOutputDirectory(String username) {
        String safeUser = text(username).replaceAll("[^A-Za-z0-9._-]", "_");
        Path output = gitDumperOutputRoot.resolve(safeUser).resolve(UUID.randomUUID().toString()).normalize();
        if (!output.startsWith(gitDumperOutputRoot)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Directorio de salida no valido");
        }
        try {
            Files.createDirectories(output);
            return output;
        } catch (IOException ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "No se pudo preparar la salida de git-dumper");
        }
    }

    private void requireAuthorized(Boolean authorized) {
        requireAuthorized(authorized, "Confirma alcance autorizado antes de ejecutar git-dumper.");
    }

    private void requireAuthorized(Boolean authorized, String message) {
        if (!Boolean.TRUE.equals(authorized)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, message);
        }
    }

    private long safeFileSize(Path file) {
        try {
            return Files.size(file);
        } catch (IOException ex) {
            return 0L;
        }
    }

    private String classifyGitDumpFile(String path) {
        String lower = path.toLowerCase(Locale.ROOT);
        if (lower.equals(".git/config") || lower.endsWith("/.git/config")) {
            return "config";
        }
        if (lower.startsWith(".git/") || lower.contains("/.git/")) {
            return "git-metadata";
        }
        if (lower.endsWith(".java") || lower.endsWith(".js") || lower.endsWith(".ts") || lower.endsWith(".vue") || lower.endsWith(".py") || lower.endsWith(".php") || lower.endsWith(".go") || lower.endsWith(".rb")) {
            return "source";
        }
        if (lower.contains("secret") || lower.endsWith(".env") || lower.contains("credential")) {
            return "sensitive-name";
        }
        return "file";
    }

    private boolean isInvalidIpv4Literal(String host) {
        if (!host.matches("^(?:\\d{1,3}\\.){3}\\d{1,3}$")) {
            return false;
        }
        for (String part : host.split("\\.")) {
            int value = parseInt(part);
            if (value < 0 || value > 255) {
                return true;
            }
        }
        return false;
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

    private Object readArbitraryJson(String json) {
        if (!hasText(json)) {
            return null;
        }
        try {
            return objectMapper.readValue(json, Object.class);
        } catch (JsonProcessingException ex) {
            return null;
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

    private int parseInt(String value) {
        try {
            return Integer.parseInt(text(value));
        } catch (Exception ex) {
            return -1;
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

    private static String firstValue(Map<?, ?> map, String... keys) {
        for (String key : keys) {
            Object value = map.get(key);
            if (value != null && hasText(String.valueOf(value))) {
                return String.valueOf(value);
            }
        }
        return "";
    }

    private static int scoreSpiderFoot(String type, String confidence) {
        String normalized = text(type).toUpperCase(Locale.ROOT);
        int score = 55;
        if (normalized.contains("PASSWORD") || normalized.contains("BREACH") || normalized.contains("LEAK")) score += 25;
        if (normalized.contains("EMAIL") || normalized.contains("PHONE") || normalized.contains("ACCOUNT")) score += 15;
        if (normalized.contains("VULNERABILITY") || normalized.contains("MALICIOUS")) score += 30;
        int confidenceValue = 0;
        try {
            confidenceValue = Integer.parseInt(text(confidence).replaceAll("[^0-9]", ""));
        } catch (Exception ignored) {
            confidenceValue = 0;
        }
        if (confidenceValue > 0) {
            score = Math.max(score, Math.min(100, confidenceValue));
        }
        return Math.min(100, score);
    }

    private static String redactSecret(String value) {
        String secret = text(value);
        if (secret.length() <= 10) {
            return hasText(secret) ? "[redacted]" : "";
        }
        return secret.substring(0, Math.min(4, secret.length())) + "..." + secret.substring(Math.max(4, secret.length() - 4));
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
