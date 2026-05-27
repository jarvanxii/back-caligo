package com.caligo.backend.metasploit;

import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessageFormat;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageUnpacker;
import org.msgpack.value.ValueType;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Component
public class MetasploitRpcClient {

    private final HttpClient httpClient;
    private final String host;
    private final int port;
    private final boolean ssl;
    private final String username;
    private final String password;
    private final long timeoutSeconds;

    private volatile String token;

    public MetasploitRpcClient(
            @Value("${caligo.metasploit.rpc.host:127.0.0.1}") String host,
            @Value("${caligo.metasploit.rpc.port:55552}") int port,
            @Value("${caligo.metasploit.rpc.ssl:false}") boolean ssl,
            @Value("${caligo.metasploit.rpc.username:caligo}") String username,
            @Value("${caligo.metasploit.rpc.password:}") String password,
            @Value("${caligo.metasploit.rpc.timeout-seconds:20}") long timeoutSeconds
    ) {
        this.host = host;
        this.port = port;
        this.ssl = ssl;
        this.username = username;
        this.password = password;
        this.timeoutSeconds = Math.max(3, timeoutSeconds);
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(this.timeoutSeconds))
                .build();
    }

    public Map<String, Object> call(String method, Object... args) {
        if (!hasText(password)) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Credenciales RPC de Metasploit no configuradas");
        }
        if ("auth.login".equals(method)) {
            return rpc(method, args);
        }
        String activeToken = ensureToken();
        List<Object> fullArgs = new ArrayList<>();
        fullArgs.add(activeToken);
        fullArgs.addAll(List.of(args));
        Map<String, Object> response = rpc(method, fullArgs.toArray());
        if (isAuthError(response)) {
            token = null;
            activeToken = ensureToken();
            fullArgs.set(0, activeToken);
            response = rpc(method, fullArgs.toArray());
        }
        return response;
    }

    public boolean available() {
        try {
            coreVersion();
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    public Map<String, Object> coreVersion() {
        return call("core.version");
    }

    public Map<String, Object> connectionInfo() {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("host", host);
        info.put("port", port);
        info.put("ssl", ssl);
        info.put("usernameConfigured", hasText(username));
        info.put("passwordConfigured", hasText(password));
        return info;
    }

    private synchronized String ensureToken() {
        if (hasText(token)) {
            return token;
        }
        Map<String, Object> login = rpc("auth.login", username, password);
        Object result = login.get("result");
        Object value = login.get("token");
        if (!"success".equals(String.valueOf(result)) || value == null) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Metasploit RPC rechazo el login");
        }
        token = String.valueOf(value);
        return token;
    }

    private Map<String, Object> rpc(String method, Object... args) {
        try {
            byte[] body = packPayload(method, args);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create((ssl ? "https" : "http") + "://" + host + ":" + port + "/api/"))
                    .timeout(Duration.ofSeconds(timeoutSeconds))
                    .header("Content-Type", "binary/message-pack")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                    .build();
            HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() >= 400) {
                throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Metasploit RPC respondio " + response.statusCode());
            }
            Map<String, Object> parsed = unpackResponse(response.body());
            if (Boolean.TRUE.equals(parsed.get("error"))) {
                throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, String.valueOf(parsed.getOrDefault("error_message", "Error RPC de Metasploit")));
            }
            return parsed;
        } catch (ResponseStatusException ex) {
            throw ex;
        } catch (IOException | InterruptedException ex) {
            if (ex instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Metasploit RPC no responde: " + sample(ex.getMessage(), 240));
        }
    }

    private byte[] packPayload(String method, Object... args) throws IOException {
        try (MessageBufferPacker packer = MessagePack.newDefaultBufferPacker()) {
            packer.packArrayHeader(1 + args.length);
            packValue(packer, method);
            for (Object arg : args) {
                packValue(packer, arg);
            }
            packer.flush();
            return packer.toByteArray();
        }
    }

    private void packValue(MessageBufferPacker packer, Object value) throws IOException {
        if (value == null) {
            packer.packNil();
        } else if (value instanceof String stringValue) {
            packer.packString(stringValue);
        } else if (value instanceof Boolean booleanValue) {
            packer.packBoolean(booleanValue);
        } else if (value instanceof Integer integerValue) {
            packer.packInt(integerValue);
        } else if (value instanceof Long longValue) {
            packer.packLong(longValue);
        } else if (value instanceof Number numberValue) {
            packer.packDouble(numberValue.doubleValue());
        } else if (value instanceof Map<?, ?> mapValue) {
            packer.packMapHeader(mapValue.size());
            for (Map.Entry<?, ?> entry : mapValue.entrySet()) {
                packValue(packer, String.valueOf(entry.getKey()));
                packValue(packer, entry.getValue());
            }
        } else if (value instanceof Collection<?> collectionValue) {
            packer.packArrayHeader(collectionValue.size());
            for (Object item : collectionValue) {
                packValue(packer, item);
            }
        } else {
            packer.packString(String.valueOf(value));
        }
    }

    private Map<String, Object> unpackResponse(byte[] body) throws IOException {
        try (MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(body)) {
            Object value = unpackValue(unpacker);
            if (value instanceof Map<?, ?> mapValue) {
                Map<String, Object> response = new LinkedHashMap<>();
                for (Map.Entry<?, ?> entry : mapValue.entrySet()) {
                    response.put(String.valueOf(entry.getKey()), entry.getValue());
                }
                return response;
            }
            throw new IOException("Respuesta RPC no valida");
        }
    }

    private Object unpackValue(MessageUnpacker unpacker) throws IOException {
        MessageFormat format = unpacker.getNextFormat();
        ValueType type = format.getValueType();
        return switch (type) {
            case NIL -> {
                unpacker.unpackNil();
                yield null;
            }
            case BOOLEAN -> unpacker.unpackBoolean();
            case INTEGER -> narrowNumber(unpacker.unpackLong());
            case FLOAT -> unpacker.unpackDouble();
            case STRING -> unpacker.unpackString();
            case BINARY -> {
                int length = unpacker.unpackBinaryHeader();
                byte[] bytes = unpacker.readPayload(length);
                yield bytes;
            }
            case ARRAY -> {
                int length = unpacker.unpackArrayHeader();
                List<Object> values = new ArrayList<>(length);
                for (int i = 0; i < length; i++) {
                    values.add(unpackValue(unpacker));
                }
                yield values;
            }
            case MAP -> {
                int length = unpacker.unpackMapHeader();
                Map<String, Object> values = new LinkedHashMap<>();
                for (int i = 0; i < length; i++) {
                    Object key = unpackValue(unpacker);
                    Object value = unpackValue(unpacker);
                    values.put(String.valueOf(key), value);
                }
                yield values;
            }
            case EXTENSION -> throw new IOException("Extension MessagePack no soportada");
        };
    }

    private Number narrowNumber(long value) {
        if (value >= Integer.MIN_VALUE && value <= Integer.MAX_VALUE) {
            return (int) value;
        }
        return value;
    }

    private boolean isAuthError(Map<String, Object> response) {
        String errorClass = String.valueOf(response.getOrDefault("error_class", ""));
        String message = String.valueOf(response.getOrDefault("error_message", ""));
        return errorClass.toLowerCase().contains("auth") || message.toLowerCase().contains("token");
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
