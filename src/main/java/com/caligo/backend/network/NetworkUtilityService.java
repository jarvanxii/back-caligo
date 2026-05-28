package com.caligo.backend.network;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class NetworkUtilityService {

    private static final Duration PUBLIC_IP_TIMEOUT = Duration.ofSeconds(5);
    private static final Duration PUBLIC_IP_CACHE_TTL = Duration.ofSeconds(25);

    private final ObjectMapper objectMapper;
    private final VpnControlService vpnControlService;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(PUBLIC_IP_TIMEOUT)
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    private volatile CachedPublicIp cachedPublicIp = new CachedPublicIp("", "", Instant.EPOCH);

    public NetworkUtilityService(ObjectMapper objectMapper, VpnControlService vpnControlService) {
        this.objectMapper = objectMapper;
        this.vpnControlService = vpnControlService;
    }

    public Map<String, Object> identity(HttpServletRequest request) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("generatedAt", Instant.now().toString());
        response.put("client", clientSnapshot(request));
        response.put("server", serverSnapshot());
        response.put("vpn", vpnControlService.status());
        return response;
    }

    private Map<String, Object> clientSnapshot(HttpServletRequest request) {
        Map<String, Object> client = new LinkedHashMap<>();
        client.put("observedIp", remoteIp(request));
        client.put("remoteAddr", request.getRemoteAddr());
        client.put("forwardedFor", header(request, "X-Forwarded-For"));
        client.put("realIp", header(request, "X-Real-IP"));
        client.put("userAgent", header(request, "User-Agent"));
        client.put("acceptLanguage", header(request, "Accept-Language"));
        client.put("origin", header(request, "Origin"));
        client.put("referer", header(request, "Referer"));
        client.put("scheme", request.getScheme());
        client.put("host", request.getHeader("Host"));
        client.put("secure", request.isSecure());
        return client;
    }

    private Map<String, Object> serverSnapshot() {
        CachedPublicIp publicIp = cachedServerPublicIp();
        Map<String, Object> server = new LinkedHashMap<>();
        server.put("publicIp", publicIp.ip());
        server.put("publicIpSource", publicIp.source());
        server.put("hostname", hostname());
        server.put("interfaces", localInterfaces());
        return server;
    }

    private CachedPublicIp cachedServerPublicIp() {
        CachedPublicIp current = cachedPublicIp;
        if (current.expiresAt().isAfter(Instant.now()) && !current.ip().isBlank()) {
            return current;
        }
        CachedPublicIp fresh = resolveServerPublicIp();
        cachedPublicIp = fresh;
        return fresh;
    }

    private CachedPublicIp resolveServerPublicIp() {
        List<IpSource> sources = List.of(
                new IpSource("api.ipify.org", "https://api.ipify.org?format=json", true),
                new IpSource("icanhazip.com", "https://icanhazip.com", false),
                new IpSource("ifconfig.me", "https://ifconfig.me/ip", false)
        );
        for (IpSource source : sources) {
            try {
                HttpRequest request = HttpRequest.newBuilder(URI.create(source.url()))
                        .timeout(PUBLIC_IP_TIMEOUT)
                        .header("Accept", source.json() ? "application/json" : "text/plain")
                        .GET()
                        .build();
                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() < 200 || response.statusCode() >= 300) {
                    continue;
                }
                String ip = source.json() ? parseIpJson(response.body()) : response.body().trim();
                if (looksLikeIp(ip)) {
                    return new CachedPublicIp(ip, source.name(), Instant.now().plus(PUBLIC_IP_CACHE_TTL));
                }
            } catch (Exception ignored) {
                // Try the next public IP source.
            }
        }
        return new CachedPublicIp("No disponible", "sin respuesta", Instant.now().plus(Duration.ofSeconds(10)));
    }

    private String parseIpJson(String body) throws Exception {
        JsonNode node = objectMapper.readTree(body);
        return node.path("ip").asText("");
    }

    private boolean looksLikeIp(String value) {
        return value != null && value.matches("^[0-9a-fA-F:.]{3,80}$");
    }

    private String hostname() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (Exception ex) {
            return "No disponible";
        }
    }

    private List<Map<String, Object>> localInterfaces() {
        List<Map<String, Object>> result = new ArrayList<>();
        try {
            for (NetworkInterface item : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!item.isUp() || item.isLoopback()) {
                    continue;
                }
                List<String> addresses = Collections.list(item.getInetAddresses()).stream()
                        .map(InetAddress::getHostAddress)
                        .filter(address -> !address.contains("%"))
                        .toList();
                if (addresses.isEmpty()) {
                    continue;
                }
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("name", item.getName());
                row.put("displayName", item.getDisplayName());
                row.put("addresses", addresses);
                result.add(row);
            }
        } catch (Exception ignored) {
            // Local interface enumeration is best-effort.
        }
        return result;
    }

    private String remoteIp(HttpServletRequest request) {
        String forwarded = header(request, "X-Forwarded-For");
        if (!forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        String realIp = header(request, "X-Real-IP");
        if (!realIp.isBlank()) {
            return realIp;
        }
        return request.getRemoteAddr();
    }

    private String header(HttpServletRequest request, String name) {
        String value = request.getHeader(name);
        return value == null ? "" : value;
    }

    private record IpSource(String name, String url, boolean json) {
    }

    private record CachedPublicIp(String ip, String source, Instant expiresAt) {
    }
}
