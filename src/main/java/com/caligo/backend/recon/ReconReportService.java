package com.caligo.backend.recon;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

@Service
public class ReconReportService {

    private static final float MARGIN = 48f;
    private static final float TOP = 790f;
    private static final float BOTTOM = 48f;
    private static final float LEADING = 14f;

    private final ToolExecutionJobRepository jobs;
    private final ObjectMapper objectMapper;

    public ReconReportService(ToolExecutionJobRepository jobs, ObjectMapper objectMapper) {
        this.jobs = jobs;
        this.objectMapper = objectMapper;
    }

    public byte[] report(UUID id, String username, String expectedTool) {
        ToolExecutionJob job = jobs.findById(id)
                .filter(item -> username.equals(item.getUsername()))
                .filter(item -> expectedTool.equals(item.getTool()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Job no encontrado"));

        try (PDDocument document = new PDDocument()) {
            PdfWriter writer = new PdfWriter(document);
            writer.header(job);
            writer.section("Resumen");
            writer.keyValue("Herramienta", job.getTool().toUpperCase(Locale.ROOT));
            writer.keyValue("Objetivo", job.getTarget());
            writer.keyValue("Estado", job.getStatus());
            writer.keyValue("Fase", value(job.getPhase()));
            writer.keyValue("Usuario", job.getUsername());
            writer.keyValue("Creado", string(job.getCreatedAt()));
            writer.keyValue("Inicio", string(job.getStartedAt()));
            writer.keyValue("Fin", string(job.getCompletedAt()));
            writer.keyValue("Duracion", duration(job.getStartedAt(), job.getCompletedAt()));
            writer.keyValue("Comando", value(job.getCommandPreview()));

            Map<String, Object> parameters = readJson(job.getParametersJson());
            if (!parameters.isEmpty()) {
                writer.section("Parametros");
                for (Map.Entry<String, Object> entry : parameters.entrySet()) {
                    writer.keyValue(entry.getKey(), value(entry.getValue()));
                }
            }

            Map<String, Object> result = readJson(job.getResultJson());
            if ("nmap".equals(job.getTool())) {
                writeNmap(writer, result);
            } else if ("openvas".equals(job.getTool())) {
                writeOpenVas(writer, result);
            }

            if (hasText(job.getErrorMessage())) {
                writer.section("Error");
                writer.paragraph(job.getErrorMessage());
            }

            writer.footer();
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            document.save(output);
            return output.toByteArray();
        } catch (IOException ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "No se pudo generar el PDF");
        }
    }

    private void writeNmap(PdfWriter writer, Map<String, Object> result) throws IOException {
        writer.section("Resultado Nmap");
        Map<String, Object> summary = asMap(result.get("summary"));
        if (!summary.isEmpty()) {
            writer.keyValue("Hosts", value(summary.get("hosts")));
            writer.keyValue("Puertos abiertos", value(summary.get("openPorts")));
            writer.keyValue("Puertos filtrados", value(summary.get("filteredPorts")));
            writer.keyValue("Puertos cerrados", value(summary.get("closedPorts")));
        }
        writer.keyValue("Scanner", value(result.get("scanner")));
        writer.keyValue("Version", value(result.get("version")));
        writer.keyValue("Inicio Nmap", value(result.get("started")));

        List<Map<String, Object>> rows = new ArrayList<>();
        for (Map<String, Object> host : asListOfMaps(result.get("hosts"))) {
            String address = value(host.get("address"));
            for (Map<String, Object> port : asListOfMaps(host.get("ports"))) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("Host", address);
                row.put("Puerto", value(port.get("protocol")) + "/" + value(port.get("port")));
                row.put("Estado", value(port.get("state")));
                row.put("Servicio", service(port));
                rows.add(row);
            }
        }
        writer.table("Puertos", List.of("Host", "Puerto", "Estado", "Servicio"), rows, 160);

        if (hasText(value(result.get("stderr")))) {
            writer.section("Salida tecnica");
            writer.paragraph(value(result.get("stderr")));
        }
    }

    private void writeOpenVas(PdfWriter writer, Map<String, Object> result) throws IOException {
        writer.section("Resultado OpenVAS");
        writer.keyValue("Task ID", value(result.get("taskId")));
        writer.keyValue("Target ID", value(result.get("targetId")));
        writer.keyValue("Report ID", value(result.get("reportId")));
        writer.keyValue("Hallazgos", value(result.get("findingCount")));
        Map<String, Object> summary = asMap(result.get("summary"));
        if (!summary.isEmpty()) {
            writer.keyValue("Criticos", value(summary.get("critical")));
            writer.keyValue("Altos", value(summary.get("high")));
            writer.keyValue("Medios", value(summary.get("medium")));
            writer.keyValue("Bajos", value(summary.get("low")));
            writer.keyValue("Info", value(summary.get("info")));
            writer.keyValue("Severidad maxima", value(summary.get("maxSeverity")));
        }

        List<Map<String, Object>> rows = new ArrayList<>();
        for (Map<String, Object> finding : asListOfMaps(result.get("findings"))) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("Sev", value(finding.get("severity")));
            row.put("Host", value(finding.get("host")));
            row.put("Puerto", value(finding.get("port")));
            row.put("Hallazgo", value(finding.get("name")));
            rows.add(row);
        }
        writer.table("Hallazgos", List.of("Sev", "Host", "Puerto", "Hallazgo"), rows, 200);

        int detailCount = 0;
        for (Map<String, Object> finding : asListOfMaps(result.get("findings"))) {
            if (detailCount >= 12) {
                break;
            }
            writer.section("Detalle: " + value(finding.get("name")));
            writer.keyValue("Severidad", value(finding.get("severity")));
            writer.keyValue("Threat", value(finding.get("threat")));
            writer.keyValue("QoD", value(finding.get("qod")));
            writer.keyValue("Familia", value(finding.get("family")));
            writer.keyValue("CVEs", value(finding.get("cves")));
            writer.paragraph(value(finding.get("description")));
            detailCount++;
        }
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

    private static Map<String, Object> asMap(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> result = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                result.put(String.valueOf(entry.getKey()), entry.getValue());
            }
            return result;
        }
        return Map.of();
    }

    private static List<Map<String, Object>> asListOfMaps(Object value) {
        if (!(value instanceof List<?> list)) {
            return List.of();
        }
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list) {
            Map<String, Object> map = asMap(item);
            if (!map.isEmpty()) {
                result.add(map);
            }
        }
        return result;
    }

    private static String service(Map<String, Object> port) {
        return List.of(value(port.get("service")), value(port.get("product")), value(port.get("version")))
                .stream()
                .filter(ReconReportService::hasText)
                .reduce((left, right) -> left + " " + right)
                .orElse("N/D");
    }

    private static String value(Object value) {
        if (value == null) {
            return "";
        }
        if (value instanceof List<?> list) {
            return list.stream().map(ReconReportService::value).filter(ReconReportService::hasText).limit(12).toList().toString();
        }
        return String.valueOf(value);
    }

    private static String string(Instant instant) {
        return instant == null ? "N/D" : instant.toString();
    }

    private static String duration(Instant startedAt, Instant completedAt) {
        if (startedAt == null) {
            return "N/D";
        }
        Duration duration = Duration.between(startedAt, completedAt == null ? Instant.now() : completedAt);
        long seconds = duration.toSeconds();
        if (seconds < 60) {
            return seconds + "s";
        }
        return (seconds / 60) + "m " + (seconds % 60) + "s";
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private static class PdfWriter {
        private final PDDocument document;
        private PDPage page;
        private PDPageContentStream content;
        private float y;
        private int pageNumber = 0;

        PdfWriter(PDDocument document) throws IOException {
            this.document = document;
            addPage();
        }

        void header(ToolExecutionJob job) throws IOException {
            drawLogo();
            text(104, 764, "CALIGO", PDType1Font.HELVETICA_BOLD, 20, 0.86f);
            text(104, 744, job.getTool().toUpperCase(Locale.ROOT) + " SECURITY REPORT", PDType1Font.HELVETICA_BOLD, 12, 0.55f);
            line(48, 724, 548, 724, 0.35f);
            y = 700;
        }

        void section(String title) throws IOException {
            ensure(38);
            y -= 10;
            text(MARGIN, y, title.toUpperCase(Locale.ROOT), PDType1Font.HELVETICA_BOLD, 11, 0.78f);
            y -= 7;
            line(MARGIN, y, 548, y, 0.18f);
            y -= 18;
        }

        void keyValue(String key, String value) throws IOException {
            ensure(24);
            text(MARGIN, y, key, PDType1Font.HELVETICA_BOLD, 8.5f, 0.5f);
            for (String line : wrap(value == null || value.isBlank() ? "N/D" : value, 75)) {
                text(172, y, line, PDType1Font.HELVETICA, 9f, 0.84f);
                y -= LEADING;
                ensure(LEADING + 4);
            }
        }

        void paragraph(String value) throws IOException {
            String text = value == null || value.isBlank() ? "Sin datos." : value;
            for (String line : wrap(text, 105)) {
                ensure(LEADING + 4);
                text(MARGIN, y, line, PDType1Font.HELVETICA, 9f, 0.84f);
                y -= LEADING;
            }
        }

        void table(String title, List<String> columns, List<Map<String, Object>> rows, int limit) throws IOException {
            if (rows.isEmpty()) {
                return;
            }
            section(title);
            ensure(24);
            float[] widths = widths(columns.size());
            float x = MARGIN;
            for (int i = 0; i < columns.size(); i++) {
                text(x, y, columns.get(i), PDType1Font.HELVETICA_BOLD, 8f, 0.54f);
                x += widths[i];
            }
            y -= 15;
            int count = 0;
            for (Map<String, Object> row : rows) {
                if (count >= limit) {
                    paragraph("Mostrando " + limit + " filas de " + rows.size() + ".");
                    return;
                }
                ensure(28);
                x = MARGIN;
                int lines = 1;
                List<List<String>> wrapped = new ArrayList<>();
                for (int i = 0; i < columns.size(); i++) {
                    String column = columns.get(i);
                    int chars = Math.max(10, Math.round(widths[i] / 5.4f));
                    List<String> cell = wrap(value(row.get(column)), chars);
                    wrapped.add(cell);
                    lines = Math.max(lines, Math.min(3, cell.size()));
                }
                for (int line = 0; line < lines; line++) {
                    x = MARGIN;
                    for (int i = 0; i < columns.size(); i++) {
                        List<String> cell = wrapped.get(i);
                        text(x, y, line < cell.size() ? cell.get(line) : "", PDType1Font.HELVETICA, 8.2f, 0.82f);
                        x += widths[i];
                    }
                    y -= 11;
                }
                line(MARGIN, y + 4, 548, y + 4, 0.08f);
                y -= 5;
                count++;
            }
        }

        void footer() throws IOException {
            if (content != null) {
                content.close();
            }
        }

        private void addPage() throws IOException {
            if (content != null) {
                content.close();
            }
            page = new PDPage(PDRectangle.A4);
            document.addPage(page);
            content = new PDPageContentStream(document, page);
            pageNumber++;
            y = TOP;
            text(MARGIN, 28, "Caligo / authorized controlled lab / page " + pageNumber, PDType1Font.HELVETICA, 7.5f, 0.45f);
        }

        private void ensure(float needed) throws IOException {
            if (y - needed < BOTTOM) {
                addPage();
            }
        }

        private void drawLogo() throws IOException {
            try {
                ClassPathResource resource = new ClassPathResource("reports/logo-login.png");
                byte[] bytes = resource.getInputStream().readAllBytes();
                PDImageXObject image = PDImageXObject.createFromByteArray(document, bytes, "caligo-logo");
                content.drawImage(image, MARGIN, 732, 42, 42);
            } catch (Exception ignored) {
                text(MARGIN, 750, "C", PDType1Font.HELVETICA_BOLD, 32, 0.84f);
            }
        }

        private void text(float x, float y, String value, PDType1Font font, float size, float gray) throws IOException {
            content.beginText();
            content.setNonStrokingColor(gray);
            content.setFont(font, size);
            content.newLineAtOffset(x, y);
            content.showText(sanitize(value));
            content.endText();
        }

        private void line(float x1, float y1, float x2, float y2, float gray) throws IOException {
            content.setStrokingColor(gray);
            content.moveTo(x1, y1);
            content.lineTo(x2, y2);
            content.stroke();
        }

        private static float[] widths(int size) {
            if (size == 4) {
                return new float[]{112, 82, 72, 234};
            }
            if (size == 3) {
                return new float[]{150, 120, 230};
            }
            return new float[]{500f / Math.max(1, size)};
        }

        private static List<String> wrap(String value, int maxChars) {
            String text = sanitize(value).replace('\n', ' ').replace('\r', ' ').trim();
            if (text.isBlank()) {
                return List.of("N/D");
            }
            List<String> lines = new ArrayList<>();
            StringBuilder current = new StringBuilder();
            for (String word : text.split("\\s+")) {
                if (word.length() > maxChars) {
                    if (!current.isEmpty()) {
                        lines.add(current.toString());
                        current = new StringBuilder();
                    }
                    for (int i = 0; i < word.length(); i += maxChars) {
                        lines.add(word.substring(i, Math.min(word.length(), i + maxChars)));
                    }
                    continue;
                }
                if (!current.isEmpty() && current.length() + word.length() + 1 > maxChars) {
                    lines.add(current.toString());
                    current = new StringBuilder();
                }
                if (!current.isEmpty()) {
                    current.append(' ');
                }
                current.append(word);
            }
            if (!current.isEmpty()) {
                lines.add(current.toString());
            }
            return lines;
        }

        private static String sanitize(String value) {
            if (value == null) {
                return "";
            }
            return value
                    .replace("á", "a")
                    .replace("é", "e")
                    .replace("í", "i")
                    .replace("ó", "o")
                    .replace("ú", "u")
                    .replace("Á", "A")
                    .replace("É", "E")
                    .replace("Í", "I")
                    .replace("Ó", "O")
                    .replace("Ú", "U")
                    .replace("ñ", "n")
                    .replace("Ñ", "N")
                    .replace("¿", "")
                    .replace("¡", "")
                    .replace("€", "EUR")
                    .replaceAll("[^\\x20-\\x7E]", " ");
        }
    }
}
