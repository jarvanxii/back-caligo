package com.caligo.backend.urls;

import com.caligo.backend.audit.AuditEvent;
import com.caligo.backend.audit.AuditEventRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.IDN;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class UrlIntelligenceService {

    private static final int MAX_HTTP_BYTES = 512 * 1024;
    private static final int MAX_PUBLIC_FILE_BYTES = 128 * 1024;
    private static final int MAX_REDIRECTS = 6;
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(8);
    private static final String USER_AGENT = "Caligo-URL-Intel/0.1 (+local authorized security lab)";

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final UrlAnalysisRepository analyses;
    private final AuditEventRepository auditEvents;

    public UrlIntelligenceService(
            ObjectMapper objectMapper,
            UrlAnalysisRepository analyses,
            AuditEventRepository auditEvents
    ) {
        this.objectMapper = objectMapper;
        this.analyses = analyses;
        this.auditEvents = auditEvents;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    public Map<String, Object> resolve(UrlAnalysisRequest request, String username, String remoteIp) {
        NormalizedTarget target = normalize(request.target(), request.allowPrivateNetworks());
        Map<String, Object> dns = fetchDnsBundle(target.host());
        validateResolvedTarget(target.host(), request.allowPrivateNetworks());
        auditEvents.save(new AuditEvent(username, "URL_DNS_RESOLVE", target.host(), remoteIp));

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("input", request.target());
        response.put("mode", "dns-resolver");
        response.put("normalized", target.toPublicMap());
        response.put("dns", dns);
        response.put("privateNetworkAllowed", request.allowPrivateNetworks());
        response.put("createdAt", Instant.now().toString());
        return response;
    }

    public Map<String, Object> inspect(UrlAnalysisRequest request, String username, String remoteIp) {
        NormalizedTarget target = normalize(request.target(), request.allowPrivateNetworks());
        audit(username, "URL_INSPECT", target.normalizedUrl(), remoteIp);

        Map<String, Object> response = baseToolResponse(request, target, "url-inspector");
        response.put("normalized", target.toPublicMap());
        return response;
    }

    public Map<String, Object> httpSecurity(UrlAnalysisRequest request, String username, String remoteIp) {
        NormalizedTarget target = normalize(request.target(), request.allowPrivateNetworks());
        validateResolvedTarget(target.host(), request.allowPrivateNetworks());
        Map<String, Object> dns = fetchDnsBundle(target.host());
        HttpProbe http = fetchHttp(target.uri(), request.allowPrivateNetworks());
        Map<String, Object> tls = fetchTls(target);
        Map<String, Object> security = evaluateSecurity(target, http, tls, dns);
        audit(username, "URL_HTTP_SECURITY", target.normalizedUrl(), remoteIp);

        Map<String, Object> response = baseToolResponse(request, target, "http-security");
        response.put("http", http.publicData());
        response.put("security", security);
        return response;
    }

    public Map<String, Object> tlsCertificate(UrlAnalysisRequest request, String username, String remoteIp) {
        NormalizedTarget target = normalize(request.target(), request.allowPrivateNetworks());
        validateResolvedTarget(target.host(), request.allowPrivateNetworks());
        audit(username, "URL_TLS_CERTIFICATE", target.normalizedUrl(), remoteIp);

        Map<String, Object> response = baseToolResponse(request, target, "tls-certificate");
        response.put("tls", fetchTls(target));
        return response;
    }

    public Map<String, Object> reputation(UrlAnalysisRequest request, String username, String remoteIp) {
        NormalizedTarget target = normalize(request.target(), request.allowPrivateNetworks());
        validateResolvedTarget(target.host(), request.allowPrivateNetworks());
        Map<String, Object> dns = fetchDnsBundle(target.host());
        audit(username, "URL_REPUTATION", target.normalizedUrl(), remoteIp);

        Map<String, Object> response = baseToolResponse(request, target, "url-reputation");
        response.put("dns", dns);
        response.put("reputation", fetchReputation(target, dns));
        return response;
    }

    public Map<String, Object> history(UrlAnalysisRequest request, String username, String remoteIp) {
        NormalizedTarget target = normalize(request.target(), request.allowPrivateNetworks());
        audit(username, "URL_HISTORY", target.host(), remoteIp);

        Map<String, Object> response = baseToolResponse(request, target, "url-history");
        response.put("history", fetchHistory(target.host()));
        return response;
    }

    public Map<String, Object> publicFiles(UrlAnalysisRequest request, String username, String remoteIp) {
        NormalizedTarget target = normalize(request.target(), request.allowPrivateNetworks());
        validateResolvedTarget(target.host(), request.allowPrivateNetworks());
        audit(username, "URL_PUBLIC_FILES", target.origin(), remoteIp);

        Map<String, Object> response = baseToolResponse(request, target, "public-files");
        response.put("publicFiles", fetchPublicFiles(target, request.allowPrivateNetworks()));
        return response;
    }

    public Map<String, Object> endpoints(UrlAnalysisRequest request, String username, String remoteIp) {
        NormalizedTarget target = normalize(request.target(), request.allowPrivateNetworks());
        validateResolvedTarget(target.host(), request.allowPrivateNetworks());
        HttpProbe http = fetchHttp(target.uri(), request.allowPrivateNetworks());
        audit(username, "URL_ENDPOINTS", target.normalizedUrl(), remoteIp);

        Map<String, Object> response = baseToolResponse(request, target, "passive-endpoints");
        response.put("http", http.publicData());
        response.put("endpoints", extractEndpoints(target, http));
        return response;
    }

    public Map<String, Object> analyze(UrlAnalysisRequest request, String username, String remoteIp) {
        long started = System.nanoTime();
        NormalizedTarget target = normalize(request.target(), request.allowPrivateNetworks());
        validateResolvedTarget(target.host(), request.allowPrivateNetworks());

        Map<String, Object> dns = fetchDnsBundle(target.host());
        HttpProbe http = fetchHttp(target.uri(), request.allowPrivateNetworks());
        Map<String, Object> tls = fetchTls(target);
        Map<String, Object> publicFiles = fetchPublicFiles(target, request.allowPrivateNetworks());
        Map<String, Object> reputation = fetchReputation(target, dns);
        Map<String, Object> history = fetchHistory(target.host());
        Map<String, Object> endpoints = extractEndpoints(target, http);
        Map<String, Object> technologies = detectTechnologies(http);
        Map<String, Object> security = evaluateSecurity(target, http, tls, dns);
        Score score = calculateScore(target, dns, http, tls, security, reputation);
        int durationMs = (int) Duration.ofNanos(System.nanoTime() - started).toMillis();

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("input", request.target());
        response.put("mode", "passive-url-intelligence");
        response.put("createdAt", Instant.now().toString());
        response.put("durationMs", durationMs);
        response.put("privateNetworkAllowed", request.allowPrivateNetworks());
        response.put("normalized", target.toPublicMap());
        response.put("score", score.value());
        response.put("verdict", score.verdict());
        response.put("verdictTone", score.tone());
        response.put("dns", dns);
        response.put("http", http.publicData());
        response.put("tls", tls);
        response.put("security", security);
        response.put("publicFiles", publicFiles);
        response.put("reputation", reputation);
        response.put("history", history);
        response.put("technologies", technologies);
        response.put("endpoints", endpoints);

        UrlAnalysis saved = analyses.save(new UrlAnalysis(
                username,
                request.target(),
                target.normalizedUrl(),
                target.host(),
                "passive-url-intelligence",
                score.value(),
                score.verdict(),
                request.allowPrivateNetworks(),
                durationMs,
                writeJson(response)
        ));
        response.put("id", saved.getId());
        auditEvents.save(new AuditEvent(username, "URL_ANALYZE", target.normalizedUrl(), remoteIp));
        return response;
    }

    private Map<String, Object> baseToolResponse(UrlAnalysisRequest request, NormalizedTarget target, String mode) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("input", request.target());
        response.put("mode", mode);
        response.put("createdAt", Instant.now().toString());
        response.put("privateNetworkAllowed", request.allowPrivateNetworks());
        response.put("normalized", target.toPublicMap());
        return response;
    }

    private void audit(String username, String action, String target, String remoteIp) {
        auditEvents.save(new AuditEvent(username, action, target, remoteIp));
    }

    public List<UrlAnalysisSummary> recent(String username, int limit) {
        return analyses.findByUsernameOrderByCreatedAtDesc(username, org.springframework.data.domain.PageRequest.of(0, Math.min(Math.max(limit, 1), 50)))
                .stream()
                .map(UrlAnalysisSummary::from)
                .toList();
    }

    public Map<String, Object> find(UUID id, String username) {
        UrlAnalysis analysis = analyses.findById(id)
                .filter(item -> username.equals(item.getUsername()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Analisis no encontrado"));
        try {
            Map<String, Object> payload = objectMapper.readValue(analysis.getResultJson(), new TypeReference<>() {
            });
            payload.put("id", analysis.getId());
            return payload;
        } catch (JsonProcessingException ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "No se pudo leer el resultado guardado");
        }
    }

    private NormalizedTarget normalize(String rawTarget, boolean allowPrivateNetworks) {
        String trimmed = rawTarget == null ? "" : rawTarget.trim();
        if (trimmed.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "El objetivo es obligatorio");
        }
        if (trimmed.length() > 1000) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "El objetivo es demasiado largo");
        }

        String withScheme = trimmed.matches("(?i)^[a-z][a-z0-9+.-]*://.*") ? trimmed : "https://" + trimmed;
        URI uri;
        try {
            uri = new URI(withScheme);
        } catch (URISyntaxException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "URL no valida");
        }

        String scheme = lower(uri.getScheme());
        if (!"http".equals(scheme) && !"https".equals(scheme)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Solo se permiten URLs HTTP o HTTPS");
        }
        if (uri.getUserInfo() != null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "No se aceptan URLs con credenciales embebidas");
        }

        String originalHost = uri.getHost();
        if (originalHost == null || originalHost.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "No se pudo identificar el host");
        }

        String asciiHost;
        try {
            asciiHost = IDN.toASCII(originalHost, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Host no valido");
        }

        int explicitPort = uri.getPort();
        int effectivePort = explicitPort == -1 ? ("https".equals(scheme) ? 443 : 80) : explicitPort;
        String path = Optional.ofNullable(uri.getRawPath()).filter(value -> !value.isBlank()).orElse("/");
        URI normalizedUri;
        try {
            normalizedUri = new URI(scheme, null, asciiHost, explicitPort, path, uri.getRawQuery(), uri.getRawFragment()).normalize();
        } catch (URISyntaxException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "No se pudo normalizar la URL");
        }

        String origin = scheme + "://" + asciiHost + (explicitPort == -1 ? "" : ":" + explicitPort);
        List<Map<String, Object>> indicators = buildTargetIndicators(trimmed, scheme, originalHost, asciiHost, effectivePort, explicitPort, allowPrivateNetworks);
        return new NormalizedTarget(
                trimmed,
                normalizedUri,
                normalizedUri.toString(),
                origin,
                scheme,
                asciiHost,
                effectivePort,
                explicitPort != -1,
                path,
                uri.getRawQuery(),
                parseQuery(uri.getRawQuery()),
                indicators
        );
    }

    private List<Map<String, Object>> buildTargetIndicators(
            String raw,
            String scheme,
            String originalHost,
            String asciiHost,
            int port,
            int explicitPort,
            boolean allowPrivateNetworks
    ) {
        List<Map<String, Object>> indicators = new ArrayList<>();
        addIndicator(indicators, "scheme-http", "HTTP sin TLS", "warning", "http".equals(scheme));
        addIndicator(indicators, "idn", "Dominio internacionalizado o punycode", "info", !originalHost.equalsIgnoreCase(asciiHost));
        addIndicator(indicators, "ip-literal", "El host es una IP literal", "info", isIpLiteral(asciiHost));
        addIndicator(indicators, "non-default-port", "Puerto no estandar", "info", explicitPort != -1 && port != 80 && port != 443);
        addIndicator(indicators, "encoded-percent", "Contiene secuencias percent-encoded", "info", raw.contains("%"));
        addIndicator(indicators, "double-encoding", "Posible doble encoding", "warning", raw.toLowerCase(Locale.ROOT).contains("%25"));
        addIndicator(indicators, "private-scope", "El usuario permite rangos privados para laboratorio local", "warning", allowPrivateNetworks);
        return indicators;
    }

    private void addIndicator(List<Map<String, Object>> indicators, String code, String label, String tone, boolean active) {
        if (!active) {
            return;
        }
        Map<String, Object> indicator = new LinkedHashMap<>();
        indicator.put("code", code);
        indicator.put("label", label);
        indicator.put("tone", tone);
        indicators.add(indicator);
    }

    private List<Map<String, String>> parseQuery(String rawQuery) {
        if (rawQuery == null || rawQuery.isBlank()) {
            return List.of();
        }
        List<Map<String, String>> params = new ArrayList<>();
        for (String pair : rawQuery.split("&")) {
            String[] parts = pair.split("=", 2);
            Map<String, String> param = new LinkedHashMap<>();
            param.put("name", urlDecode(parts[0]));
            param.put("value", parts.length > 1 ? urlDecode(parts[1]) : "");
            params.add(param);
        }
        return params;
    }

    private Map<String, Object> fetchDnsBundle(String host) {
        Map<String, Object> bundle = new LinkedHashMap<>();
        for (String type : List.of("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA")) {
            bundle.put(type.toLowerCase(Locale.ROOT), fetchDnsRecords(host, type));
        }
        bundle.put("resolvedByServer", resolveJava(host));
        return bundle;
    }

    private Map<String, Object> fetchDnsRecords(String host, String type) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("type", type);
        result.put("success", false);
        result.put("records", List.of());

        String encodedName = URLEncoder.encode(host, StandardCharsets.UTF_8);
        URI uri = URI.create("https://dns.google/resolve?name=" + encodedName + "&type=" + type);
        try {
            HttpRequest request = baseRequest(uri).GET().build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            result.put("httpStatus", response.statusCode());
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                result.put("error", "dns.google respondio con HTTP " + response.statusCode());
                return result;
            }

            Map<String, Object> raw = objectMapper.readValue(response.body(), new TypeReference<>() {
            });
            result.put("success", true);
            result.put("status", raw.get("Status"));
            result.put("records", normalizeDnsAnswers(raw.get("Answer")));
            return result;
        } catch (IOException ex) {
            result.put("error", ex.getMessage());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            result.put("error", "interrupted");
        }
        return result;
    }

    private List<Map<String, Object>> normalizeDnsAnswers(Object answers) {
        if (!(answers instanceof Collection<?> collection)) {
            return List.of();
        }
        List<Map<String, Object>> records = new ArrayList<>();
        for (Object item : collection) {
            if (!(item instanceof Map<?, ?> answer)) {
                continue;
            }
            Map<String, Object> record = new LinkedHashMap<>();
            record.put("name", answer.get("name"));
            record.put("ttl", answer.get("TTL"));
            record.put("type", answer.get("type"));
            record.put("data", answer.get("data"));
            records.add(record);
        }
        return records;
    }

    private List<Map<String, Object>> resolveJava(String host) {
        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            List<Map<String, Object>> resolved = new ArrayList<>();
            for (InetAddress address : addresses) {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("address", address.getHostAddress());
                item.put("family", address instanceof Inet6Address ? "IPv6" : "IPv4");
                item.put("private", isPrivateAddress(address));
                resolved.add(item);
            }
            return resolved;
        } catch (IOException ex) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("error", ex.getMessage());
            return List.of(item);
        }
    }

    private void validateResolvedTarget(String host, boolean allowPrivateNetworks) {
        if (allowPrivateNetworks) {
            return;
        }
        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress address : addresses) {
                if (isPrivateAddress(address)) {
                    throw new ResponseStatusException(
                            HttpStatus.BAD_REQUEST,
                            "Destino bloqueado por proteccion anti-SSRF. Activa el modo de laboratorio local si es un objetivo autorizado."
                    );
                }
            }
        } catch (IOException ex) {
            if (validateWithDohFallback(host)) {
                return;
            }
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "No se pudo resolver el host antes de analizarlo");
        }
    }

    private boolean validateWithDohFallback(String host) {
        List<Map<String, Object>> records = new ArrayList<>();
        records.addAll(listOfMaps(fetchDnsRecords(host, "A").get("records")));
        records.addAll(listOfMaps(fetchDnsRecords(host, "AAAA").get("records")));
        if (records.isEmpty()) {
            return false;
        }

        for (Map<String, Object> record : records) {
            Object data = record.get("data");
            if (data == null) {
                return false;
            }
            try {
                InetAddress address = InetAddress.getByName(String.valueOf(data));
                if (isPrivateAddress(address)) {
                    return false;
                }
            } catch (IOException ex) {
                return false;
            }
        }
        return true;
    }

    private boolean isPrivateAddress(InetAddress address) {
        if (address.isAnyLocalAddress()
                || address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isMulticastAddress()) {
            return true;
        }
        byte[] bytes = address.getAddress();
        if (address instanceof Inet4Address && bytes.length == 4) {
            int first = bytes[0] & 0xff;
            int second = bytes[1] & 0xff;
            return first == 0
                    || first == 10
                    || first == 127
                    || (first == 169 && second == 254)
                    || (first == 172 && second >= 16 && second <= 31)
                    || (first == 192 && second == 168);
        }
        if (address instanceof Inet6Address && bytes.length == 16) {
            int first = bytes[0] & 0xff;
            return (first & 0xfe) == 0xfc;
        }
        return false;
    }

    private HttpProbe fetchHttp(URI startUri, boolean allowPrivateNetworks) {
        Map<String, Object> data = new LinkedHashMap<>();
        List<Map<String, Object>> redirects = new ArrayList<>();
        URI current = startUri;
        String body = "";
        Map<String, List<String>> headers = Map.of();
        int status = 0;

        for (int index = 0; index <= MAX_REDIRECTS; index++) {
            validateResolvedTarget(current.getHost(), allowPrivateNetworks);
            try {
                HttpRequest request = baseRequest(current)
                        .header("Accept", "text/html,application/xhtml+xml,application/json,text/plain,*/*;q=0.8")
                        .GET()
                        .build();
                HttpResponse<InputStream> response = httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
                status = response.statusCode();
                headers = response.headers().map();
                body = readCapped(response.body(), MAX_HTTP_BYTES);

                Optional<String> location = firstHeader(headers, "location");
                if (status >= 300 && status < 400 && location.isPresent() && index < MAX_REDIRECTS) {
                    URI next = current.resolve(location.get());
                    Map<String, Object> redirect = new LinkedHashMap<>();
                    redirect.put("status", status);
                    redirect.put("from", current.toString());
                    redirect.put("to", next.toString());
                    redirects.add(redirect);
                    current = next;
                    continue;
                }

                data.put("success", true);
                data.put("status", status);
                data.put("initialUrl", startUri.toString());
                data.put("finalUrl", current.toString());
                data.put("redirects", redirects);
                data.put("headers", headersToEntries(headers));
                data.put("cookies", parseCookies(headers));
                data.put("contentType", firstHeader(headers, "content-type").orElse(""));
                data.put("bodyBytesCaptured", body.getBytes(StandardCharsets.UTF_8).length);
                data.put("truncated", body.getBytes(StandardCharsets.UTF_8).length >= MAX_HTTP_BYTES);
                return new HttpProbe(data, body, headers, current, status);
            } catch (IOException ex) {
                data.put("success", false);
                data.put("error", ex.getMessage());
                data.put("initialUrl", startUri.toString());
                data.put("finalUrl", current.toString());
                data.put("redirects", redirects);
                return new HttpProbe(data, body, headers, current, status);
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                data.put("success", false);
                data.put("error", "interrupted");
                return new HttpProbe(data, body, headers, current, status);
            }
        }

        data.put("success", false);
        data.put("error", "Demasiadas redirecciones");
        data.put("initialUrl", startUri.toString());
        data.put("finalUrl", current.toString());
        data.put("redirects", redirects);
        return new HttpProbe(data, body, headers, current, status);
    }

    private Map<String, Object> fetchTls(NormalizedTarget target) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", false);
        result.put("enabled", "https".equals(target.scheme()));
        if (!"https".equals(target.scheme())) {
            result.put("error", "La URL usa HTTP, no hay handshake TLS que analizar");
            return result;
        }

        try {
            SSLSocketFactory factory = SSLContext.getDefault().getSocketFactory();
            try (SSLSocket socket = (SSLSocket) factory.createSocket(target.host(), target.port())) {
                socket.setSoTimeout((int) REQUEST_TIMEOUT.toMillis());
                SSLParameters parameters = socket.getSSLParameters();
                parameters.setServerNames(List.of(new SNIHostName(target.host())));
                parameters.setEndpointIdentificationAlgorithm("HTTPS");
                socket.setSSLParameters(parameters);
                socket.startHandshake();

                Certificate[] certificates = socket.getSession().getPeerCertificates();
                X509Certificate certificate = (X509Certificate) certificates[0];
                boolean validNow = true;
                try {
                    certificate.checkValidity();
                } catch (Exception ex) {
                    validNow = false;
                }

                result.put("success", true);
                result.put("protocol", socket.getSession().getProtocol());
                result.put("cipherSuite", socket.getSession().getCipherSuite());
                result.put("subject", certificate.getSubjectX500Principal().getName());
                result.put("issuer", certificate.getIssuerX500Principal().getName());
                result.put("serialNumber", certificate.getSerialNumber().toString(16));
                result.put("signatureAlgorithm", certificate.getSigAlgName());
                result.put("notBefore", certificate.getNotBefore().toInstant().toString());
                result.put("notAfter", certificate.getNotAfter().toInstant().toString());
                result.put("daysRemaining", ChronoUnit.DAYS.between(Instant.now(), certificate.getNotAfter().toInstant()));
                result.put("validNow", validNow);
                result.put("sha256", fingerprint(certificate));
                result.put("subjectAlternativeNames", subjectAlternativeNames(certificate));
                result.put("chainLength", certificates.length);
            }
        } catch (Exception ex) {
            result.put("error", ex.getMessage());
        }
        return result;
    }

    private List<String> subjectAlternativeNames(X509Certificate certificate) {
        try {
            Collection<List<?>> names = certificate.getSubjectAlternativeNames();
            if (names == null) {
                return List.of();
            }
            List<String> values = new ArrayList<>();
            for (List<?> name : names) {
                if (name.size() >= 2 && name.get(1) != null) {
                    values.add(String.valueOf(name.get(1)));
                }
            }
            return values.stream().distinct().limit(60).toList();
        } catch (Exception ex) {
            return List.of();
        }
    }

    private String fingerprint(X509Certificate certificate) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
        StringBuilder builder = new StringBuilder();
        for (byte value : digest) {
            if (!builder.isEmpty()) {
                builder.append(':');
            }
            builder.append(String.format("%02X", value));
        }
        return builder.toString();
    }

    private Map<String, Object> fetchPublicFiles(NormalizedTarget target, boolean allowPrivateNetworks) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (String path : List.of("/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/security.txt", "/humans.txt", "/ads.txt", "/.well-known/change-password")) {
            result.put(keyForPublicPath(path), fetchPublicText(target.origin() + path, allowPrivateNetworks));
        }
        return result;
    }

    private Map<String, Object> fetchPublicText(String url, boolean allowPrivateNetworks) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("url", url);
        result.put("success", false);
        try {
            URI uri = URI.create(url);
            validateResolvedTarget(uri.getHost(), allowPrivateNetworks);
            HttpRequest request = baseRequest(uri).GET().build();
            HttpResponse<InputStream> response = httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
            String body = readCapped(response.body(), MAX_PUBLIC_FILE_BYTES);
            result.put("status", response.statusCode());
            result.put("success", response.statusCode() >= 200 && response.statusCode() < 300);
            result.put("contentType", firstHeader(response.headers().map(), "content-type").orElse(""));
            result.put("size", body.length());
            result.put("sample", sample(body, 5000));
        } catch (IOException ex) {
            result.put("error", ex.getMessage());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            result.put("error", "interrupted");
        }
        return result;
    }

    private Map<String, Object> fetchReputation(NormalizedTarget target, Map<String, Object> dns) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("urlhaus", fetchUrlHaus(target.normalizedUrl()));
        result.put("urlscan", fetchUrlScan(target.host()));
        result.put("virustotal", fetchVirusTotal(target.normalizedUrl()));
        result.put("abuseIpDb", fetchAbuseIpDb(firstDnsAddress(dns)));
        result.put("safeBrowsing", fetchSafeBrowsing(target.normalizedUrl()));
        return result;
    }

    private Map<String, Object> fetchUrlHaus(String url) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", false);
        try {
            String body = "url=" + URLEncoder.encode(url, StandardCharsets.UTF_8);
            HttpRequest request = baseRequest(URI.create("https://urlhaus-api.abuse.ch/v1/url/"))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            result.put("httpStatus", response.statusCode());
            result.put("success", response.statusCode() >= 200 && response.statusCode() < 300);
            result.put("raw", objectMapper.readValue(response.body(), new TypeReference<Map<String, Object>>() {
            }));
        } catch (IOException ex) {
            result.put("error", ex.getMessage());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            result.put("error", "interrupted");
        }
        return result;
    }

    private Map<String, Object> fetchUrlScan(String host) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", false);
        try {
            URI uri = URI.create("https://urlscan.io/api/v1/search/?q=domain:" + URLEncoder.encode(host, StandardCharsets.UTF_8));
            HttpResponse<String> response = httpClient.send(baseRequest(uri).GET().build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            result.put("httpStatus", response.statusCode());
            result.put("success", response.statusCode() >= 200 && response.statusCode() < 300);
            if (Boolean.TRUE.equals(result.get("success"))) {
                Map<String, Object> raw = objectMapper.readValue(response.body(), new TypeReference<>() {
                });
                result.put("total", raw.getOrDefault("total", 0));
                result.put("results", compactUrlScanResults(raw.get("results")));
            } else {
                result.put("error", sample(response.body(), 400));
            }
        } catch (IOException ex) {
            result.put("error", ex.getMessage());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            result.put("error", "interrupted");
        }
        return result;
    }

    private List<Map<String, Object>> compactUrlScanResults(Object rawResults) {
        if (!(rawResults instanceof Collection<?> collection)) {
            return List.of();
        }
        List<Map<String, Object>> results = new ArrayList<>();
        for (Object item : collection) {
            if (!(item instanceof Map<?, ?> raw)) {
                continue;
            }
            Map<String, Object> compact = new LinkedHashMap<>();
            compact.put("task", raw.get("task"));
            compact.put("page", raw.get("page"));
            compact.put("verdicts", raw.get("verdicts"));
            results.add(compact);
            if (results.size() >= 8) {
                break;
            }
        }
        return results;
    }

    private Map<String, Object> fetchVirusTotal(String url) {
        String apiKey = System.getenv("CALIGO_VIRUSTOTAL_API_KEY");
        if (apiKey == null || apiKey.isBlank()) {
            return notConfigured("CALIGO_VIRUSTOTAL_API_KEY");
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", false);
        try {
            String id = Base64.getUrlEncoder().withoutPadding().encodeToString(url.getBytes(StandardCharsets.UTF_8));
            HttpRequest request = baseRequest(URI.create("https://www.virustotal.com/api/v3/urls/" + id))
                    .header("x-apikey", apiKey)
                    .GET()
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            result.put("httpStatus", response.statusCode());
            result.put("success", response.statusCode() >= 200 && response.statusCode() < 300);
            result.put("raw", objectMapper.readValue(response.body(), new TypeReference<Map<String, Object>>() {
            }));
        } catch (IOException ex) {
            result.put("error", ex.getMessage());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            result.put("error", "interrupted");
        }
        return result;
    }

    private Map<String, Object> fetchAbuseIpDb(String ipAddress) {
        String apiKey = System.getenv("CALIGO_ABUSEIPDB_API_KEY");
        if (apiKey == null || apiKey.isBlank()) {
            return notConfigured("CALIGO_ABUSEIPDB_API_KEY");
        }
        if (ipAddress == null || ipAddress.isBlank()) {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("success", false);
            result.put("status", "no_ip");
            result.put("message", "No hay IP A disponible para consultar AbuseIPDB");
            return result;
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", false);
        try {
            URI uri = URI.create("https://api.abuseipdb.com/api/v2/check?maxAgeInDays=90&ipAddress=" + URLEncoder.encode(ipAddress, StandardCharsets.UTF_8));
            HttpRequest request = baseRequest(uri)
                    .header("Key", apiKey)
                    .header("Accept", "application/json")
                    .GET()
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            result.put("httpStatus", response.statusCode());
            result.put("success", response.statusCode() >= 200 && response.statusCode() < 300);
            result.put("raw", objectMapper.readValue(response.body(), new TypeReference<Map<String, Object>>() {
            }));
        } catch (IOException ex) {
            result.put("error", ex.getMessage());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            result.put("error", "interrupted");
        }
        return result;
    }

    private Map<String, Object> fetchSafeBrowsing(String url) {
        String apiKey = System.getenv("CALIGO_SAFE_BROWSING_API_KEY");
        if (apiKey == null || apiKey.isBlank()) {
            return notConfigured("CALIGO_SAFE_BROWSING_API_KEY");
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", false);
        try {
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("client", Map.of("clientId", "caligo-local", "clientVersion", "0.1.0"));
            payload.put("threatInfo", Map.of(
                    "threatTypes", List.of("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"),
                    "platformTypes", List.of("ANY_PLATFORM"),
                    "threatEntryTypes", List.of("URL"),
                    "threatEntries", List.of(Map.of("url", url))
            ));
            HttpRequest request = baseRequest(URI.create("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + URLEncoder.encode(apiKey, StandardCharsets.UTF_8)))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(payload)))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            result.put("httpStatus", response.statusCode());
            result.put("success", response.statusCode() >= 200 && response.statusCode() < 300);
            result.put("raw", objectMapper.readValue(response.body().isBlank() ? "{}" : response.body(), new TypeReference<Map<String, Object>>() {
            }));
        } catch (IOException ex) {
            result.put("error", ex.getMessage());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            result.put("error", "interrupted");
        }
        return result;
    }

    private Map<String, Object> notConfigured(String envVar) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", false);
        result.put("status", "not_configured");
        result.put("envVar", envVar);
        result.put("message", "Define " + envVar + " en local para activar esta fuente.");
        return result;
    }

    private Map<String, Object> fetchHistory(String host) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("rdap", fetchRdap(host));
        result.put("certificateTransparency", fetchCertificateTransparency(host));
        result.put("wayback", fetchWayback(host));
        return result;
    }

    private Map<String, Object> fetchRdap(String host) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", false);
        try {
            URI uri = URI.create("https://rdap.org/domain/" + URLEncoder.encode(host, StandardCharsets.UTF_8));
            HttpResponse<String> response = httpClient.send(baseRequest(uri).GET().build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            result.put("httpStatus", response.statusCode());
            result.put("success", response.statusCode() >= 200 && response.statusCode() < 300);
            if (Boolean.TRUE.equals(result.get("success"))) {
                Map<String, Object> raw = objectMapper.readValue(response.body(), new TypeReference<>() {
                });
                result.put("ldhName", raw.get("ldhName"));
                result.put("status", raw.get("status"));
                result.put("nameservers", compactRdapNameservers(raw.get("nameservers")));
                result.put("events", raw.get("events"));
            } else {
                result.put("error", sample(response.body(), 400));
            }
        } catch (IOException ex) {
            result.put("error", ex.getMessage());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            result.put("error", "interrupted");
        }
        return result;
    }

    private List<String> compactRdapNameservers(Object rawNameservers) {
        if (!(rawNameservers instanceof Collection<?> collection)) {
            return List.of();
        }
        List<String> names = new ArrayList<>();
        for (Object item : collection) {
            if (item instanceof Map<?, ?> map && map.get("ldhName") != null) {
                names.add(String.valueOf(map.get("ldhName")));
            }
        }
        return names.stream().distinct().sorted().toList();
    }

    private Map<String, Object> fetchCertificateTransparency(String host) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", false);
        try {
            URI uri = URI.create("https://crt.sh/?q=" + URLEncoder.encode("%." + host, StandardCharsets.UTF_8) + "&output=json");
            HttpResponse<String> response = httpClient.send(baseRequest(uri).GET().build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            result.put("httpStatus", response.statusCode());
            result.put("success", response.statusCode() >= 200 && response.statusCode() < 300);
            if (!Boolean.TRUE.equals(result.get("success")) || response.body().isBlank()) {
                result.put("error", response.body().isBlank() ? "Sin respuesta" : sample(response.body(), 400));
                return result;
            }

            List<Map<String, Object>> raw = objectMapper.readValue(response.body(), new TypeReference<>() {
            });
            Set<String> names = new LinkedHashSet<>();
            for (Map<String, Object> entry : raw) {
                Object value = entry.get("name_value");
                if (value != null) {
                    for (String name : String.valueOf(value).split("\\R")) {
                        names.add(name.replace("*.", "").trim().toLowerCase(Locale.ROOT));
                    }
                }
            }
            result.put("count", names.size());
            result.put("names", names.stream().filter(value -> !value.isBlank()).sorted().limit(80).toList());
        } catch (IOException ex) {
            result.put("error", ex.getMessage());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            result.put("error", "interrupted");
        }
        return result;
    }

    private Map<String, Object> fetchWayback(String host) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", false);
        try {
            String query = "https://web.archive.org/cdx?url=" + URLEncoder.encode(host + "/*", StandardCharsets.UTF_8)
                    + "&output=json&fl=timestamp,original,statuscode,mimetype&collapse=urlkey&limit=30";
            HttpResponse<String> response = httpClient.send(baseRequest(URI.create(query)).GET().build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            result.put("httpStatus", response.statusCode());
            result.put("success", response.statusCode() >= 200 && response.statusCode() < 300);
            if (!Boolean.TRUE.equals(result.get("success")) || response.body().isBlank()) {
                result.put("error", response.body().isBlank() ? "Sin datos" : sample(response.body(), 400));
                return result;
            }

            List<List<Object>> raw = objectMapper.readValue(response.body(), new TypeReference<>() {
            });
            List<Map<String, Object>> captures = new ArrayList<>();
            for (int index = 1; index < raw.size(); index++) {
                List<Object> row = raw.get(index);
                if (row.size() < 4) {
                    continue;
                }
                Map<String, Object> capture = new LinkedHashMap<>();
                capture.put("timestamp", row.get(0));
                capture.put("url", row.get(1));
                capture.put("status", row.get(2));
                capture.put("mime", row.get(3));
                captures.add(capture);
            }
            result.put("count", captures.size());
            result.put("captures", captures);
        } catch (IOException ex) {
            result.put("error", ex.getMessage());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            result.put("error", "interrupted");
        }
        return result;
    }

    private Map<String, Object> extractEndpoints(NormalizedTarget target, HttpProbe http) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", false);
        result.put("links", List.of());
        result.put("scripts", List.of());
        result.put("forms", List.of());

        String contentType = firstHeader(http.headers(), "content-type").orElse("").toLowerCase(Locale.ROOT);
        if (http.body().isBlank() || !contentType.contains("html")) {
            result.put("error", "No hay HTML suficiente para extraer endpoints pasivos");
            return result;
        }

        result.put("success", true);
        result.put("links", extractAttributeUrls(target, http, "href"));
        result.put("scripts", extractAttributeUrls(target, http, "src").stream()
                .filter(item -> String.valueOf(item.get("url")).contains(".js") || String.valueOf(item.get("source")).contains("script"))
                .toList());
        result.put("forms", extractAttributeUrls(target, http, "action"));
        return result;
    }

    private List<Map<String, Object>> extractAttributeUrls(NormalizedTarget target, HttpProbe http, String attribute) {
        Pattern pattern = Pattern.compile("(?i)(<[^>]+?\\s" + Pattern.quote(attribute) + "\\s*=\\s*[\"']([^\"']{1,700})[\"'][^>]*>)");
        Matcher matcher = pattern.matcher(http.body());
        List<Map<String, Object>> urls = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        while (matcher.find() && urls.size() < 80) {
            String raw = matcher.group(2).trim();
            if (raw.startsWith("javascript:") || raw.startsWith("mailto:") || raw.startsWith("#")) {
                continue;
            }
            try {
                URI resolved = http.finalUri().resolve(raw);
                if (!seen.add(resolved.toString())) {
                    continue;
                }
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("source", attribute);
                item.put("raw", raw);
                item.put("url", resolved.toString());
                item.put("internal", target.host().equalsIgnoreCase(resolved.getHost()));
                urls.add(item);
            } catch (IllegalArgumentException ignored) {
                // Ignore malformed links collected from HTML.
            }
        }
        return urls;
    }

    private Map<String, Object> detectTechnologies(HttpProbe http) {
        Map<String, Object> result = new LinkedHashMap<>();
        List<Map<String, Object>> indicators = new ArrayList<>();
        addTech(indicators, "server", firstHeader(http.headers(), "server").orElse(""));
        addTech(indicators, "x-powered-by", firstHeader(http.headers(), "x-powered-by").orElse(""));
        addTech(indicators, "via", firstHeader(http.headers(), "via").orElse(""));
        addTech(indicators, "cdn", firstHeader(http.headers(), "cf-ray").isPresent() ? "Cloudflare" : "");

        String body = http.body().toLowerCase(Locale.ROOT);
        addTech(indicators, "framework", body.contains("wp-content") ? "WordPress" : "");
        addTech(indicators, "framework", body.contains("data-v-") || body.contains("vue") ? "Vue" : "");
        addTech(indicators, "framework", body.contains("__next") ? "Next.js" : "");
        addTech(indicators, "framework", body.contains("react") ? "React" : "");
        addTech(indicators, "framework", body.contains("bootstrap") ? "Bootstrap" : "");

        result.put("indicators", indicators);
        result.put("count", indicators.size());
        return result;
    }

    private void addTech(List<Map<String, Object>> indicators, String source, String value) {
        if (value == null || value.isBlank()) {
            return;
        }
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("source", source);
        item.put("value", value);
        indicators.add(item);
    }

    private Map<String, Object> evaluateSecurity(NormalizedTarget target, HttpProbe http, Map<String, Object> tls, Map<String, Object> dns) {
        List<Map<String, Object>> checks = new ArrayList<>();
        addCheck(checks, "https", "HTTPS", "https".equals(target.scheme()), "critical", "La URL debe usar TLS.");
        addCheck(checks, "tls-valid", "Certificado TLS valido", Boolean.TRUE.equals(tls.get("validNow")), "critical", "Certificado actual, confiable y dentro de fecha.");
        addCheck(checks, "hsts", "Strict-Transport-Security", hasHeader(http.headers(), "strict-transport-security"), "high", "Evita downgrade a HTTP.");
        addCheck(checks, "csp", "Content-Security-Policy", hasHeader(http.headers(), "content-security-policy"), "high", "Reduce impacto de XSS e inyecciones.");
        addCheck(checks, "x-frame-options", "X-Frame-Options", hasHeader(http.headers(), "x-frame-options"), "medium", "Mitiga clickjacking en navegadores antiguos.");
        addCheck(checks, "x-content-type-options", "X-Content-Type-Options", firstHeader(http.headers(), "x-content-type-options").orElse("").equalsIgnoreCase("nosniff"), "medium", "Evita MIME sniffing.");
        addCheck(checks, "referrer-policy", "Referrer-Policy", hasHeader(http.headers(), "referrer-policy"), "medium", "Controla fuga de origen y rutas.");
        addCheck(checks, "permissions-policy", "Permissions-Policy", hasHeader(http.headers(), "permissions-policy"), "medium", "Reduce APIs del navegador expuestas.");
        addCheck(checks, "coop", "Cross-Origin-Opener-Policy", hasHeader(http.headers(), "cross-origin-opener-policy"), "low", "Aislamiento de contexto.");
        addCheck(checks, "corp", "Cross-Origin-Resource-Policy", hasHeader(http.headers(), "cross-origin-resource-policy"), "low", "Control de carga cross-origin.");
        addCheck(checks, "caa", "CAA publicado", dnsRecords(dns, "caa").size() > 0, "low", "Limita autoridades certificadoras.");

        boolean corsWildcard = firstHeader(http.headers(), "access-control-allow-origin").orElse("").trim().equals("*");
        addCheck(checks, "cors-wildcard", "CORS wildcard", !corsWildcard, "medium", "Revisar si '*' es intencional.");

        long passed = checks.stream().filter(item -> Boolean.TRUE.equals(item.get("passed"))).count();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("checks", checks);
        result.put("passed", passed);
        result.put("total", checks.size());
        result.put("grade", gradeFromRatio(passed, checks.size()));
        return result;
    }

    private void addCheck(List<Map<String, Object>> checks, String code, String label, boolean passed, String severity, String note) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("code", code);
        item.put("label", label);
        item.put("passed", passed);
        item.put("severity", severity);
        item.put("note", note);
        checks.add(item);
    }

    private Score calculateScore(
            NormalizedTarget target,
            Map<String, Object> dns,
            HttpProbe http,
            Map<String, Object> tls,
            Map<String, Object> security,
            Map<String, Object> reputation
    ) {
        int score = 100;
        if (!"https".equals(target.scheme())) {
            score -= 22;
        }
        if (!Boolean.TRUE.equals(http.publicData().get("success"))) {
            score -= 14;
        }
        if (http.status() >= 400) {
            score -= 10;
        }
        if ("https".equals(target.scheme()) && !Boolean.TRUE.equals(tls.get("validNow"))) {
            score -= 24;
        }
        Object days = tls.get("daysRemaining");
        if (days instanceof Number number && number.longValue() < 14) {
            score -= 10;
        }
        List<Map<String, Object>> checks = listOfMaps(security.get("checks"));
        for (Map<String, Object> check : checks) {
            if (!Boolean.TRUE.equals(check.get("passed"))) {
                score -= switch (String.valueOf(check.get("severity"))) {
                    case "critical" -> 10;
                    case "high" -> 8;
                    case "medium" -> 5;
                    default -> 2;
                };
            }
        }
        score -= target.indicators().stream().filter(item -> "warning".equals(item.get("tone"))).count() * 4;
        if (isUrlHausHit(reputation)) {
            score = Math.min(score, 10);
        }
        if (dnsRecords(dns, "a").isEmpty() && dnsRecords(dns, "aaaa").isEmpty()) {
            score -= 12;
        }
        score = Math.max(0, Math.min(100, score));

        String verdict = score >= 82 ? "Postura saludable" : score >= 58 ? "Mejorable" : "Riesgo alto";
        String tone = score >= 82 ? "success" : score >= 58 ? "warning" : "danger";
        return new Score(score, verdict, tone);
    }

    private boolean isUrlHausHit(Map<String, Object> reputation) {
        Object urlhausRaw = mapValue(reputation.get("urlhaus"), "raw");
        if (urlhausRaw instanceof Map<?, ?> map) {
            return "ok".equals(String.valueOf(map.get("query_status")));
        }
        return false;
    }

    private String gradeFromRatio(long passed, int total) {
        if (total == 0) {
            return "N/D";
        }
        double ratio = (double) passed / total;
        if (ratio >= 0.9) {
            return "A";
        }
        if (ratio >= 0.76) {
            return "B";
        }
        if (ratio >= 0.6) {
            return "C";
        }
        if (ratio >= 0.45) {
            return "D";
        }
        return "E";
    }

    private HttpRequest.Builder baseRequest(URI uri) {
        return HttpRequest.newBuilder(uri)
                .timeout(REQUEST_TIMEOUT)
                .header("User-Agent", USER_AGENT);
    }

    private String readCapped(InputStream stream, int maxBytes) throws IOException {
        try (InputStream input = stream; ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int total = 0;
            int read;
            while ((read = input.read(buffer, 0, Math.min(buffer.length, Math.max(1, maxBytes - total)))) != -1) {
                output.write(buffer, 0, read);
                total += read;
                if (total >= maxBytes) {
                    break;
                }
            }
            return output.toString(StandardCharsets.UTF_8);
        }
    }

    private Optional<String> firstHeader(Map<String, List<String>> headers, String name) {
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name) && !entry.getValue().isEmpty()) {
                return Optional.ofNullable(entry.getValue().getFirst());
            }
        }
        return Optional.empty();
    }

    private boolean hasHeader(Map<String, List<String>> headers, String name) {
        return firstHeader(headers, name).filter(value -> !value.isBlank()).isPresent();
    }

    private List<Map<String, Object>> headersToEntries(Map<String, List<String>> headers) {
        return headers.entrySet()
                .stream()
                .sorted(Comparator.comparing(entry -> entry.getKey().toLowerCase(Locale.ROOT)))
                .map(entry -> {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("name", entry.getKey());
                    item.put("values", entry.getValue());
                    return item;
                })
                .toList();
    }

    private List<Map<String, Object>> parseCookies(Map<String, List<String>> headers) {
        List<Map<String, Object>> cookies = new ArrayList<>();
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            if (!entry.getKey().equalsIgnoreCase("set-cookie")) {
                continue;
            }
            for (String raw : entry.getValue()) {
                Map<String, Object> cookie = new LinkedHashMap<>();
                String[] parts = raw.split(";");
                String[] nameValue = parts[0].split("=", 2);
                cookie.put("name", nameValue[0].trim());
                cookie.put("secure", raw.toLowerCase(Locale.ROOT).contains("; secure"));
                cookie.put("httpOnly", raw.toLowerCase(Locale.ROOT).contains("; httponly"));
                cookie.put("sameSite", raw.toLowerCase(Locale.ROOT).contains("samesite"));
                cookies.add(cookie);
            }
        }
        return cookies;
    }

    private List<Map<String, Object>> dnsRecords(Map<String, Object> dns, String type) {
        Object section = dns.get(type.toLowerCase(Locale.ROOT));
        Object records = mapValue(section, "records");
        return listOfMaps(records);
    }

    private String firstDnsAddress(Map<String, Object> dns) {
        List<Map<String, Object>> records = dnsRecords(dns, "a");
        if (records.isEmpty()) {
            return null;
        }
        Object value = records.getFirst().get("data");
        return value == null ? null : String.valueOf(value);
    }

    private Object mapValue(Object source, String key) {
        if (source instanceof Map<?, ?> map) {
            return map.get(key);
        }
        return null;
    }

    private List<Map<String, Object>> listOfMaps(Object source) {
        if (!(source instanceof Collection<?> collection)) {
            return List.of();
        }
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : collection) {
            if (item instanceof Map<?, ?> raw) {
                Map<String, Object> map = new LinkedHashMap<>();
                for (Map.Entry<?, ?> entry : raw.entrySet()) {
                    map.put(String.valueOf(entry.getKey()), entry.getValue());
                }
                result.add(map);
            }
        }
        return result;
    }

    private String keyForPublicPath(String path) {
        return path.replace("/.well-known/", "")
                .replace("/", "")
                .replace(".", "_")
                .replace("-", "_");
    }

    private String lower(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ROOT);
    }

    private String urlDecode(String value) {
        try {
            return java.net.URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ex) {
            return value;
        }
    }

    private String sample(String value, int max) {
        if (value == null) {
            return "";
        }
        if (value.length() <= max) {
            return value;
        }
        return value.substring(0, max);
    }

    private boolean isIpLiteral(String host) {
        return host.matches("^\\d{1,3}(\\.\\d{1,3}){3}$") || host.contains(":");
    }

    private String writeJson(Map<String, Object> response) {
        try {
            return objectMapper.writeValueAsString(response);
        } catch (JsonProcessingException ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "No se pudo serializar el analisis");
        }
    }

    private record NormalizedTarget(
            String input,
            URI uri,
            String normalizedUrl,
            String origin,
            String scheme,
            String host,
            int port,
            boolean explicitPort,
            String path,
            String query,
            List<Map<String, String>> queryParams,
            List<Map<String, Object>> indicators
    ) {
        Map<String, Object> toPublicMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("url", normalizedUrl);
            map.put("origin", origin);
            map.put("scheme", scheme);
            map.put("host", host);
            map.put("port", port);
            map.put("explicitPort", explicitPort);
            map.put("path", path);
            map.put("query", query);
            map.put("queryParams", queryParams);
            map.put("indicators", indicators);
            return map;
        }
    }

    private record HttpProbe(
            Map<String, Object> publicData,
            String body,
            Map<String, List<String>> headers,
            URI finalUri,
            int status
    ) {
    }

    private record Score(int value, String verdict, String tone) {
    }
}
