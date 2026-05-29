package com.caligo.backend.osint;

import com.caligo.backend.audit.AuditEvent;
import com.caligo.backend.audit.AuditEventRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.net.IDN;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class OsintExposureService {

    private static final Pattern SAFE_DOMAIN = Pattern.compile("(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,30}$");
    private static final Pattern SAFE_PATH = Pattern.compile("^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,180}$");
    private static final Pattern EMAIL_PATTERN = Pattern.compile("[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,24}");
    private static final Pattern PHONE_PATTERN = Pattern.compile("(?:(?:\\+|00)\\d[\\d .()/-]{6,}\\d|\\b\\d[\\d .()/-]{7,}\\d\\b)");
    private static final Pattern META_TAG_PATTERN = Pattern.compile("<meta\\s+[^>]*(?:name|property)=[\"']?([^\"'>\\s]+)[\"']?[^>]*content=[\"']([^\"']{1,240})[\"'][^>]*>", Pattern.CASE_INSENSITIVE);
    private static final Pattern PDF_INFO_PATTERN = Pattern.compile("/(Author|Creator|Producer|Title|Subject)\\s*\\(([^)]{1,220})\\)");
    private static final Set<String> ROLE_ACCOUNTS = Set.of("admin", "administrator", "root", "postmaster", "abuse", "security", "support", "help", "info", "contact", "sales", "billing", "press", "legal", "privacy");
    private static final Map<String, String> COUNTRY_PREFIXES = Map.ofEntries(
            Map.entry("ES", "+34"),
            Map.entry("SPAIN", "+34"),
            Map.entry("ESPANA", "+34"),
            Map.entry("ESPAÑA", "+34"),
            Map.entry("US", "+1"),
            Map.entry("USA", "+1"),
            Map.entry("FR", "+33"),
            Map.entry("DE", "+49"),
            Map.entry("IT", "+39"),
            Map.entry("PT", "+351"),
            Map.entry("UK", "+44"),
            Map.entry("GB", "+44")
    );
    private static final List<String> CONTACT_PATHS = List.of(
            "/.well-known/security.txt",
            "/security.txt",
            "/contact",
            "/contacto",
            "/about",
            "/privacy",
            "/legal",
            "/robots.txt",
            "/sitemap.xml"
    );
    private static final List<String> PUBLIC_FILE_PATHS = List.of(
            "/robots.txt",
            "/sitemap.xml",
            "/.well-known/security.txt",
            "/security.txt",
            "/humans.txt",
            "/.well-known/change-password",
            "/ads.txt",
            "/app-ads.txt",
            "/crossdomain.xml",
            "/clientaccesspolicy.xml"
    );
    private static final String USER_AGENT = "Caligo-OSINT-Exposure/0.1 (+authorized security lab)";

    private final AuditEventRepository auditEvents;
    private final HttpClient httpClient;

    public OsintExposureService(AuditEventRepository auditEvents) {
        this.auditEvents = auditEvents;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(8))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    public Map<String, Object> capabilities() {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("tools", List.of(
                serverTool("email-exposure", "Email Exposure", "Analisis seguro de formato, dominio, MX y candidatos profesionales."),
                serverTool("phone-lookup", "Phone Lookup", "Normalizacion y validacion del telefono aportado por el usuario."),
                serverTool("domain-contacts", "Domain Contacts", "Extraccion de contactos publicados por un dominio autorizado."),
                serverTool("password-exposure", "Password Exposure Check", "Comprobacion k-anon contra Pwned Passwords sin enviar el secreto completo."),
                serverTool("metadata-exposure", "Metadata Exposure", "Cabeceras y metadatos visibles de documentos publicos."),
                serverTool("public-files", "Public Files", "Inventario de ficheros publicos habituales del dominio.")
        ));
        response.put("providers", Map.of(
                "pwnedPasswordsKAnon", true,
                "dnsMx", true,
                "domainHttpFetch", true
        ));
        response.put("defaults", Map.of(
                "contactPaths", CONTACT_PATHS,
                "publicFilePaths", PUBLIC_FILE_PATHS,
                "countryHints", List.of("ES", "US", "FR", "DE", "IT", "PT", "UK")
        ));
        return response;
    }

    public Map<String, Object> emailExposure(EmailExposureRequest request, String username, String remoteIp) {
        requireAuthorized(request.authorized());
        String email = lower(request.email());
        String domain = hasText(email) ? email.substring(email.indexOf('@') + 1) : normalizeDomain(request.domain());
        if (hasText(email) && !EMAIL_PATTERN.matcher(email).matches()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email no valido");
        }
        if (!hasText(domain)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Indica email o dominio");
        }
        domain = normalizeDomain(domain);
        auditEvents.save(new AuditEvent(username, "OSINT_EMAIL_EXPOSURE", hasText(email) ? email : domain, remoteIp));

        List<String> mxRecords = resolveMxRecords(domain);
        List<Map<String, Object>> findings = new ArrayList<>();
        findings.add(finding("domain", domain, "dominio", "Dominio normalizado para el analisis.", 70));
        findings.add(finding("mx", mxRecords.isEmpty() ? "sin MX" : String.join(", ", mxRecords), "dns", mxRecords.isEmpty() ? "No se han localizado registros MX publicos." : "El dominio publica registros MX.", mxRecords.isEmpty() ? 35 : 80));

        if (hasText(email)) {
            String localPart = email.substring(0, email.indexOf('@'));
            findings.add(finding("email", email, "entrada", "Formato de email valido para comprobaciones OSINT controladas.", 75));
            if (ROLE_ACCOUNTS.contains(localPart.toLowerCase(Locale.ROOT))) {
                findings.add(finding("role-account", localPart, "clasificacion", "Cuenta generica o departamental. Suele aparecer publicada y no identifica por si sola a una persona.", 60));
            }
        }

        List<String> candidates = Boolean.FALSE.equals(request.generateCandidates())
                ? List.of()
                : generateEmailCandidates(request.fullName(), domain);
        if (!candidates.isEmpty()) {
            findings.add(finding("candidates", String.valueOf(candidates.size()), "patrones", "Candidatos profesionales generados desde nombre y dominio; no se verifica existencia de buzon.", 58));
        }

        Map<String, Object> response = base("email-exposure");
        response.put("target", hasText(email) ? email : domain);
        response.put("domain", domain);
        response.put("mxRecords", mxRecords);
        response.put("candidates", candidates);
        response.put("queries", searchQueries(hasText(email) ? email : domain, List.of("email", "linkedin", "github", "paste", "contact")));
        response.put("findings", findings);
        response.put("summary", Map.of(
                "email", hasText(email) ? email : "no aportado",
                "domain", domain,
                "mx", mxRecords.size(),
                "candidates", candidates.size()
        ));
        response.put("recommendations", List.of(
                "Contrasta cualquier candidato con fuentes publicas independientes antes de atribuir identidad.",
                "No uses SMTP VRFY ni intentos de login para verificar buzones desde esta vista.",
                "Usa Domain Contacts o theHarvester si necesitas ampliar contactos publicados por el dominio."
        ));
        return response;
    }

    public Map<String, Object> phoneLookup(PhoneLookupRequest request, String username, String remoteIp) {
        requireAuthorized(request.authorized());
        String raw = text(request.phone());
        auditEvents.save(new AuditEvent(username, "OSINT_PHONE_LOOKUP", sample(raw, 80), remoteIp));

        String digits = raw.replaceAll("[^0-9+]", "");
        String prefix = countryPrefix(request.countryHint());
        String e164 = normalizePhone(digits, prefix);
        String compact = e164.replaceAll("\\D", "");
        boolean possible = compact.length() >= 8 && compact.length() <= 15;
        String country = inferCountry(e164, request.countryHint());
        String type = inferPhoneType(e164, country);

        List<Map<String, Object>> findings = new ArrayList<>();
        findings.add(finding(possible ? "phone-normalized" : "phone-invalid", e164, "normalizacion", possible ? "Numero normalizado en formato E.164 aproximado." : "El numero no encaja en una longitud telefonica habitual.", possible ? 75 : 25));
        findings.add(finding("scope", country, "pais", "Pais inferido desde prefijo o pista aportada.", 55));
        findings.add(finding("type", type, "clasificacion", "Clasificacion local aproximada; no consulta bases privadas ni descubre titulares.", 50));

        Map<String, Object> response = base("phone-lookup");
        response.put("input", raw);
        response.put("normalized", Map.of(
                "e164", e164,
                "digits", compact,
                "country", country,
                "possible", possible,
                "type", type
        ));
        response.put("queries", searchQueries(e164, List.of("phone", "web", "linkedin")));
        response.put("findings", findings);
        response.put("summary", Map.of("possible", possible, "country", country, "type", type));
        response.put("recommendations", List.of(
                "Esta herramienta valida un telefono aportado, no descubre telefonos ocultos.",
                "Busca solo numeros propios, corporativos o expresamente autorizados.",
                "Si necesitas atribucion, documenta la fuente publica exacta donde aparece el numero."
        ));
        return response;
    }

    public Map<String, Object> domainContacts(DomainContactsRequest request, String username, String remoteIp) {
        requireAuthorized(request.authorized());
        String domain = normalizeDomain(request.domain());
        int timeout = clamp(value(request.timeoutSeconds(), 12), 5, 45);
        List<String> paths = sanitizePaths(request.paths(), CONTACT_PATHS);
        auditEvents.save(new AuditEvent(username, "OSINT_DOMAIN_CONTACTS", domain, remoteIp));

        List<Map<String, Object>> resources = new ArrayList<>();
        LinkedHashSet<String> emails = new LinkedHashSet<>();
        LinkedHashSet<String> phones = new LinkedHashSet<>();
        LinkedHashSet<String> urls = new LinkedHashSet<>();
        for (String path : paths) {
            FetchResult fetched = fetchFirst(domain, path, timeout);
            if (fetched == null) {
                resources.add(resource(path, "no-response", 0, "", "", 0));
                continue;
            }
            resources.add(resource(fetched.uri().toString(), String.valueOf(fetched.status()), fetched.status(), contentType(fetched), sample(fetched.body(), 240), fetched.durationMs()));
            if (fetched.status() < 400) {
                emails.addAll(extractEmails(fetched.body()));
                phones.addAll(extractPhones(fetched.body()));
                urls.addAll(extractUrls(fetched.body()));
            }
        }

        List<Map<String, Object>> findings = new ArrayList<>();
        emails.stream().limit(80).forEach(email -> findings.add(finding("email", email, "dominio", "Email publicado en una pagina del dominio.", 78)));
        phones.stream().limit(40).forEach(phone -> findings.add(finding("phone", phone, "dominio", "Telefono publicado en una pagina del dominio.", 68)));
        urls.stream().limit(60).forEach(url -> findings.add(finding("url", url, "dominio", "URL relacionada localizada durante la extraccion.", 52)));

        Map<String, Object> response = base("domain-contacts");
        response.put("domain", domain);
        response.put("resources", resources);
        response.put("emails", emails.stream().limit(80).toList());
        response.put("phones", phones.stream().limit(40).toList());
        response.put("urls", urls.stream().limit(60).toList());
        response.put("findings", findings);
        response.put("summary", Map.of(
                "resources", resources.size(),
                "emails", emails.size(),
                "phones", phones.size(),
                "urls", urls.size()
        ));
        response.put("recommendations", List.of(
                "Prioriza security.txt, paginas legales y contacto para canales responsables.",
                "Los telefonos publicados pueden ser centralitas o soporte; evita atribuirlos a personas concretas sin fuente clara.",
                "Cruza los emails con theHarvester si necesitas ampliar la huella publica del dominio."
        ));
        return response;
    }

    public Map<String, Object> passwordExposure(PasswordExposureRequest request, String username, String remoteIp) {
        requireAuthorized(request.authorized());
        String sha1 = sha1Hex(request.password());
        String prefix = sha1.substring(0, 5);
        auditEvents.save(new AuditEvent(username, "OSINT_PASSWORD_EXPOSURE", "sha1-prefix:" + prefix, remoteIp));

        try {
            HttpRequest httpRequest = HttpRequest.newBuilder(URI.create("https://api.pwnedpasswords.com/range/" + prefix))
                    .timeout(Duration.ofSeconds(18))
                    .header("User-Agent", USER_AGENT)
                    .header("Add-Padding", "true")
                    .GET()
                    .build();
            HttpResponse<String> httpResponse = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (httpResponse.statusCode() >= 400) {
                throw new IllegalStateException("Pwned Passwords respondio con HTTP " + httpResponse.statusCode());
            }
            String suffix = sha1.substring(5);
            int count = httpResponse.body().lines()
                    .map(String::trim)
                    .filter(line -> line.regionMatches(true, 0, suffix, 0, suffix.length()))
                    .map(line -> line.split(":", 2))
                    .filter(parts -> parts.length == 2)
                    .mapToInt(parts -> parseInt(parts[1]))
                    .findFirst()
                    .orElse(0);
            boolean exposed = count > 0;
            Map<String, Object> response = base("password-exposure");
            response.put("exposed", exposed);
            response.put("count", count);
            response.put("hashPrefix", prefix);
            response.put("provider", "Pwned Passwords k-anonymity");
            response.put("findings", List.of(finding(exposed ? "password-exposed" : "password-not-found", exposed ? "expuesta" : "no encontrada", "pwned-passwords-range", exposed ? "El hash aparece en el corpus publico de Pwned Passwords." : "No se ha encontrado el hash en la respuesta k-anon.", exposed ? 90 : 72)));
            response.put("summary", Map.of("exposed", exposed, "count", count, "hashPrefix", prefix));
            response.put("recommendations", exposed
                    ? List.of("No uses esta password. Cambiala, evita reutilizacion y activa MFA.", "Caligo no envia la password completa al proveedor; solo el prefijo SHA-1 de 5 caracteres.")
                    : List.of("No aparecer en Pwned Passwords no garantiza que sea fuerte.", "Evalua longitud, entropia y reutilizacion antes de aprobarla."));
            return response;
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "No se pudo consultar Pwned Passwords: " + sample(ex.getMessage(), 180));
        }
    }

    public Map<String, Object> publicFiles(PublicFilesRequest request, String username, String remoteIp) {
        requireAuthorized(request.authorized());
        String domain = normalizeTargetDomain(request.target());
        int timeout = clamp(value(request.timeoutSeconds(), 12), 5, 45);
        List<String> paths = sanitizePaths(request.paths(), PUBLIC_FILE_PATHS);
        auditEvents.save(new AuditEvent(username, "OSINT_PUBLIC_FILES", domain, remoteIp));

        List<Map<String, Object>> resources = new ArrayList<>();
        List<Map<String, Object>> findings = new ArrayList<>();
        for (String path : paths) {
            FetchResult fetched = fetchFirst(domain, path, timeout);
            if (fetched == null) {
                resources.add(resource(path, "no-response", 0, "", "", 0));
                continue;
            }
            Map<String, Object> row = resource(fetched.uri().toString(), String.valueOf(fetched.status()), fetched.status(), contentType(fetched), sample(fetched.body(), 280), fetched.durationMs());
            row.put("contentLength", contentLength(fetched));
            resources.add(row);
            if (fetched.status() < 400) {
                findings.add(finding("public-file", fetched.uri().toString(), "http", "Fichero publico accesible con HTTP " + fetched.status() + ".", scorePublicPath(path)));
                extractEmails(fetched.body()).stream().limit(20).forEach(email -> findings.add(finding("email", email, "contenido", "Email visible dentro de " + path + ".", 72)));
            }
        }

        Map<String, Object> response = base("public-files");
        response.put("domain", domain);
        response.put("resources", resources);
        response.put("findings", findings);
        response.put("summary", Map.of(
                "checked", resources.size(),
                "found", resources.stream().filter(item -> number(item.get("statusCode")) > 0 && number(item.get("statusCode")) < 400).count(),
                "findings", findings.size()
        ));
        response.put("recommendations", List.of(
                "security.txt y change-password son positivos si estan publicados de forma intencional.",
                "robots.txt y sitemap.xml pueden revelar rutas sensibles; revisa si exponen paneles o backups.",
                "No descargues ficheros grandes ni privados desde esta vista."
        ));
        return response;
    }

    public Map<String, Object> metadataExposure(MetadataExposureRequest request, String username, String remoteIp) {
        requireAuthorized(request.authorized());
        URI uri = normalizePublicUrl(request.url());
        auditEvents.save(new AuditEvent(username, "OSINT_METADATA_EXPOSURE", uri.getHost(), remoteIp));

        FetchResult fetched = fetch(uri, 18);
        List<Map<String, Object>> findings = new ArrayList<>();
        headersOfInterest(fetched).forEach((key, value) -> findings.add(finding("header", key + ": " + value, "http", "Cabecera potencialmente util para fingerprint o trazabilidad.", 58)));

        String body = fetched.body();
        Matcher metaMatcher = META_TAG_PATTERN.matcher(body);
        while (metaMatcher.find() && findings.size() < 80) {
            findings.add(finding("html-meta", metaMatcher.group(1) + "=" + metaMatcher.group(2), "html", "Meta tag publico del documento.", 50));
        }
        Matcher pdfMatcher = PDF_INFO_PATTERN.matcher(body);
        while (pdfMatcher.find() && findings.size() < 120) {
            findings.add(finding("pdf-info", pdfMatcher.group(1) + "=" + pdfMatcher.group(2), "pdf", "Campo de informacion PDF visible en la muestra descargada.", 68));
        }
        if (body.contains("Exif") || body.contains("exif")) {
            findings.add(finding("exif-marker", "Exif", "binary", "La muestra contiene marcador Exif; conviene analizar el fichero con ExifTool local.", 65));
        }

        Map<String, Object> response = base("metadata-exposure");
        response.put("url", uri.toString());
        response.put("status", fetched.status());
        response.put("contentType", contentType(fetched));
        response.put("headers", headersOfInterest(fetched));
        response.put("findings", findings);
        response.put("summary", Map.of(
                "status", fetched.status(),
                "headers", headersOfInterest(fetched).size(),
                "findings", findings.size(),
                "contentType", contentType(fetched)
        ));
        response.put("recommendations", List.of(
                "Si el fichero es propio, descarga la muestra y revisala con ExifTool o Metadata Analyzer.",
                "Cabeceras como Server, X-Powered-By o Generator pueden ampliar fingerprint tecnico.",
                "Elimina metadatos de autor, rutas internas y generadores antes de publicar documentos sensibles."
        ));
        return response;
    }

    private Map<String, Object> serverTool(String id, String label, String description) {
        return Map.of(
                "id", id,
                "label", label,
                "binary", "backend-http",
                "available", true,
                "version", "server-side",
                "description", description
        );
    }

    private FetchResult fetchFirst(String domain, String path, int timeoutSeconds) {
        URI https = URI.create("https://" + domain + path);
        try {
            return fetch(https, timeoutSeconds);
        } catch (Exception ignored) {
            try {
                return fetch(URI.create("http://" + domain + path), timeoutSeconds);
            } catch (Exception ignoredAgain) {
                return null;
            }
        }
    }

    private FetchResult fetch(URI uri, int timeoutSeconds) {
        Instant started = Instant.now();
        try {
            HttpRequest request = HttpRequest.newBuilder(uri)
                    .timeout(Duration.ofSeconds(timeoutSeconds))
                    .header("User-Agent", USER_AGENT)
                    .GET()
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return new FetchResult(uri, response.statusCode(), response.headers().map(), sample(response.body(), 120000), Duration.between(started, Instant.now()).toMillis());
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "No se pudo consultar " + uri + ": " + sample(ex.getMessage(), 160));
        }
    }

    private List<String> resolveMxRecords(String domain) {
        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
            DirContext context = new InitialDirContext(env);
            Attributes attributes = context.getAttributes(domain, new String[]{"MX"});
            if (attributes.get("MX") == null) {
                return List.of();
            }
            List<String> records = new ArrayList<>();
            for (int i = 0; i < attributes.get("MX").size(); i++) {
                records.add(String.valueOf(attributes.get("MX").get(i)).replaceFirst("^\\d+\\s+", "").replaceFirst("\\.$", ""));
            }
            return records.stream().sorted().limit(20).toList();
        } catch (Exception ex) {
            return List.of();
        }
    }

    private List<String> generateEmailCandidates(String fullName, String domain) {
        String clean = text(fullName).toLowerCase(Locale.ROOT)
                .replaceAll("[^\\p{L}\\p{N} ]", " ")
                .replaceAll("\\s+", " ")
                .trim();
        if (!hasText(clean) || clean.length() < 3) {
            return List.of();
        }
        String ascii = java.text.Normalizer.normalize(clean, java.text.Normalizer.Form.NFD)
                .replaceAll("\\p{M}", "")
                .replace("ñ", "n");
        String[] parts = ascii.split("\\s+");
        if (parts.length < 2) {
            return List.of();
        }
        String first = parts[0];
        String last = parts[parts.length - 1];
        LinkedHashSet<String> candidates = new LinkedHashSet<>();
        candidates.add(first + "." + last + "@" + domain);
        candidates.add(first + last + "@" + domain);
        candidates.add(first.charAt(0) + last + "@" + domain);
        candidates.add(first + last.charAt(0) + "@" + domain);
        candidates.add(first + "_" + last + "@" + domain);
        candidates.add(first + "-" + last + "@" + domain);
        candidates.add(first + "@" + domain);
        candidates.add(last + "@" + domain);
        return candidates.stream()
                .filter(value -> EMAIL_PATTERN.matcher(value).matches())
                .limit(12)
                .toList();
    }

    private List<String> extractEmails(String value) {
        String body = deobfuscate(value);
        return EMAIL_PATTERN.matcher(body)
                .results()
                .map(MatchResult::group)
                .map(item -> item.toLowerCase(Locale.ROOT))
                .distinct()
                .limit(120)
                .toList();
    }

    private List<String> extractPhones(String value) {
        return PHONE_PATTERN.matcher(value == null ? "" : value)
                .results()
                .map(MatchResult::group)
                .map(String::trim)
                .filter(item -> item.replaceAll("\\D", "").length() >= 8)
                .distinct()
                .limit(80)
                .toList();
    }

    private List<String> extractUrls(String value) {
        Pattern pattern = Pattern.compile("https?://[^\\s\"'<>\\])}]+", Pattern.CASE_INSENSITIVE);
        return pattern.matcher(value == null ? "" : value)
                .results()
                .map(MatchResult::group)
                .map(item -> item.replaceAll("[,.;]+$", ""))
                .distinct()
                .limit(100)
                .toList();
    }

    private String deobfuscate(String value) {
        return String.valueOf(value)
                .replaceAll("(?i)\\s+\\[?at\\]?\\s+", "@")
                .replaceAll("(?i)\\s+\\(?arroba\\)?\\s+", "@")
                .replaceAll("(?i)\\s+\\[?dot\\]?\\s+", ".")
                .replaceAll("(?i)\\s+\\(?punto\\)?\\s+", ".");
    }

    private List<Map<String, Object>> searchQueries(String target, List<String> modes) {
        return modes.stream()
                .map(mode -> {
                    String query = switch (mode) {
                        case "linkedin" -> "\"" + target + "\" site:linkedin.com/in";
                        case "github" -> "\"" + target + "\" site:github.com";
                        case "paste" -> "\"" + target + "\" paste OR leak OR breach";
                        case "contact" -> "\"" + target + "\" contact OR contacto OR security.txt";
                        case "phone" -> "\"" + target + "\"";
                        default -> "\"" + target + "\"";
                    };
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("platform", mode);
                    row.put("query", query);
                    row.put("url", "https://duckduckgo.com/html/?q=" + URLEncoder.encode(query, StandardCharsets.UTF_8));
                    return row;
                })
                .toList();
    }

    private Map<String, String> headersOfInterest(FetchResult fetched) {
        List<String> interesting = List.of("server", "x-powered-by", "x-generator", "via", "last-modified", "etag", "content-type", "content-disposition", "x-aspnet-version", "x-drupal-cache", "x-pingback");
        Map<String, String> headers = new LinkedHashMap<>();
        for (String name : interesting) {
            List<String> values = fetched.headers().getOrDefault(name, fetched.headers().getOrDefault(toTitleHeader(name), List.of()));
            if (!values.isEmpty()) {
                headers.put(name, sample(String.join(", ", values), 240));
            }
        }
        return headers;
    }

    private String contentType(FetchResult fetched) {
        return fetched.headers().entrySet().stream()
                .filter(entry -> entry.getKey().equalsIgnoreCase("content-type"))
                .findFirst()
                .map(entry -> String.join(", ", entry.getValue()))
                .orElse("");
    }

    private long contentLength(FetchResult fetched) {
        return fetched.headers().entrySet().stream()
                .filter(entry -> entry.getKey().equalsIgnoreCase("content-length"))
                .findFirst()
                .map(Map.Entry::getValue)
                .filter(values -> !values.isEmpty())
                .map(values -> parseLong(values.get(0)))
                .orElse(0L);
    }

    private Map<String, Object> base(String tool) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("tool", tool);
        response.put("generatedAt", Instant.now().toString());
        return response;
    }

    private Map<String, Object> finding(String type, String value, String source, String evidence, int score) {
        Map<String, Object> finding = new LinkedHashMap<>();
        finding.put("type", type);
        finding.put("value", value);
        finding.put("source", source);
        finding.put("evidence", evidence);
        finding.put("score", score);
        return finding;
    }

    private Map<String, Object> resource(String url, String status, int statusCode, String contentType, String sample, long durationMs) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("url", url);
        row.put("status", status);
        row.put("statusCode", statusCode);
        row.put("contentType", contentType);
        row.put("sample", sample);
        row.put("durationMs", durationMs);
        return row;
    }

    private List<String> sanitizePaths(List<String> requested, List<String> defaults) {
        if (requested == null || requested.isEmpty()) {
            return defaults;
        }
        return requested.stream()
                .map(OsintExposureService::text)
                .filter(path -> SAFE_PATH.matcher(path).matches())
                .distinct()
                .limit(18)
                .toList();
    }

    private String normalizeTargetDomain(String target) {
        String value = text(target);
        if (value.startsWith("http://") || value.startsWith("https://")) {
            return normalizePublicUrl(value).getHost();
        }
        return normalizeDomain(value);
    }

    private URI normalizePublicUrl(String value) {
        String raw = text(value);
        if (!raw.startsWith("http://") && !raw.startsWith("https://")) {
            raw = "https://" + raw;
        }
        try {
            URI uri = URI.create(raw);
            String scheme = text(uri.getScheme()).toLowerCase(Locale.ROOT);
            if (!Set.of("http", "https").contains(scheme)) {
                throw new IllegalArgumentException("scheme");
            }
            String host = normalizeDomain(uri.getHost());
            String path = hasText(uri.getRawPath()) ? uri.getRawPath() : "/";
            String query = hasText(uri.getRawQuery()) ? "?" + uri.getRawQuery() : "";
            return URI.create(scheme + "://" + host + path + query);
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "URL publica no valida");
        }
    }

    private String normalizeDomain(String value) {
        String domain = text(value).toLowerCase(Locale.ROOT)
                .replaceFirst("^https?://", "")
                .replaceFirst("/.*$", "")
                .replaceFirst(":\\d+$", "");
        try {
            domain = IDN.toASCII(domain);
        } catch (Exception ignored) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Dominio no valido");
        }
        if (!SAFE_DOMAIN.matcher(domain).matches()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Dominio no valido");
        }
        return domain;
    }

    private String normalizePhone(String digits, String prefix) {
        String value = text(digits);
        if (value.startsWith("00")) {
            value = "+" + value.substring(2);
        }
        if (value.startsWith("+")) {
            return "+" + value.substring(1).replaceAll("\\D", "");
        }
        String compact = value.replaceAll("\\D", "");
        if (!hasText(compact)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Telefono no valido");
        }
        return prefix + compact;
    }

    private String countryPrefix(String hint) {
        String normalized = java.text.Normalizer.normalize(text(hint).toUpperCase(Locale.ROOT), java.text.Normalizer.Form.NFD)
                .replaceAll("\\p{M}", "");
        return COUNTRY_PREFIXES.getOrDefault(normalized, "+34");
    }

    private String inferCountry(String e164, String hint) {
        if (hasText(hint)) {
            return text(hint).toUpperCase(Locale.ROOT);
        }
        return COUNTRY_PREFIXES.entrySet().stream()
                .filter(entry -> e164.startsWith(entry.getValue()))
                .sorted(Comparator.comparingInt(entry -> -entry.getValue().length()))
                .map(Map.Entry::getKey)
                .findFirst()
                .orElse("UNKNOWN");
    }

    private String inferPhoneType(String e164, String country) {
        if (e164.startsWith("+346") || e164.startsWith("+347")) {
            return "movil probable";
        }
        if (e164.startsWith("+349")) {
            return "fijo/servicio probable";
        }
        if (e164.startsWith("+1")) {
            return "NANP";
        }
        return hasText(country) ? "linea telefonica probable" : "desconocido";
    }

    private void requireAuthorized(Boolean authorized) {
        if (!Boolean.TRUE.equals(authorized)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Confirma que tienes autorizacion o consentimiento para esta comprobacion OSINT.");
        }
    }

    private int scorePublicPath(String path) {
        if (path.contains("security") || path.contains("change-password")) {
            return 70;
        }
        if (path.contains("robots") || path.contains("sitemap")) {
            return 58;
        }
        return 46;
    }

    private String sha1Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder();
            for (byte item : hash) {
                builder.append(String.format("%02X", item));
            }
            return builder.toString();
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "No se pudo calcular SHA-1");
        }
    }

    private String toTitleHeader(String value) {
        StringBuilder builder = new StringBuilder();
        for (String part : value.split("-")) {
            if (builder.length() > 0) {
                builder.append('-');
            }
            builder.append(part.substring(0, 1).toUpperCase(Locale.ROOT)).append(part.substring(1));
        }
        return builder.toString();
    }

    private static String lower(String value) {
        return text(value).toLowerCase(Locale.ROOT);
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

    private static int value(Integer value, int fallback) {
        return value == null ? fallback : value;
    }

    private static int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }

    private static int parseInt(String value) {
        try {
            return Integer.parseInt(text(value));
        } catch (Exception ex) {
            return 0;
        }
    }

    private static long parseLong(String value) {
        try {
            return Long.parseLong(text(value));
        } catch (Exception ex) {
            return 0;
        }
    }

    private static int number(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        return parseInt(String.valueOf(value));
    }

    private static String sample(String value, int maxChars) {
        String cleaned = value == null ? "" : value.replaceAll("\\u001B\\[[;\\d]*m", "");
        if (cleaned.length() <= maxChars) {
            return cleaned;
        }
        return cleaned.substring(0, Math.max(0, maxChars - 18)) + "\n[...truncado...]";
    }

    private record FetchResult(URI uri, int status, Map<String, List<String>> headers, String body, long durationMs) {
    }
}
