package com.caligo.backend.recon;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "tool_execution_jobs")
public class ToolExecutionJob {

    @Id
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(length = 36)
    private UUID id;

    @Column(nullable = false, length = 80)
    private String username;

    @Column(nullable = false, length = 40)
    private String tool;

    @Column(nullable = false, length = 240)
    private String target;

    @Column(nullable = false, length = 30)
    private String status;

    @Column(nullable = false)
    private int progress;

    @Column(length = 160)
    private String phase;

    @Lob
    @Column(name = "parameters_json", nullable = false, columnDefinition = "text")
    private String parametersJson;

    @Lob
    @Column(name = "result_json", columnDefinition = "longtext")
    private String resultJson;

    @Lob
    @Column(name = "error_message", columnDefinition = "text")
    private String errorMessage;

    @Column(name = "command_preview", length = 1200)
    private String commandPreview;

    @Column(name = "started_at")
    private Instant startedAt;

    @Column(name = "completed_at")
    private Instant completedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected ToolExecutionJob() {
    }

    public ToolExecutionJob(String username, String tool, String target, String parametersJson, String commandPreview) {
        this.id = UUID.randomUUID();
        this.username = username;
        this.tool = tool;
        this.target = target;
        this.parametersJson = parametersJson;
        this.commandPreview = commandPreview;
        this.status = "QUEUED";
        this.progress = 0;
        this.phase = "En cola";
    }

    @PrePersist
    void onCreate() {
        Instant now = Instant.now();
        createdAt = now;
        updatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = Instant.now();
    }

    public UUID getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getTool() {
        return tool;
    }

    public String getTarget() {
        return target;
    }

    public String getStatus() {
        return status;
    }

    public int getProgress() {
        return progress;
    }

    public String getPhase() {
        return phase;
    }

    public String getParametersJson() {
        return parametersJson;
    }

    public String getResultJson() {
        return resultJson;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public String getCommandPreview() {
        return commandPreview;
    }

    public Instant getStartedAt() {
        return startedAt;
    }

    public Instant getCompletedAt() {
        return completedAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void markRunning(String phase) {
        this.status = "RUNNING";
        this.startedAt = this.startedAt == null ? Instant.now() : this.startedAt;
        this.phase = phase;
        this.progress = Math.max(progress, 3);
    }

    public void updateProgress(int progress, String phase) {
        this.progress = Math.max(0, Math.min(99, progress));
        this.phase = phase;
    }

    public void markCompleted(String resultJson) {
        this.status = "COMPLETED";
        this.progress = 100;
        this.phase = "Completado";
        this.resultJson = resultJson;
        this.completedAt = Instant.now();
    }

    public void markFailed(String errorMessage, String resultJson) {
        this.status = "FAILED";
        this.progress = Math.max(progress, 100);
        this.phase = "Error";
        this.errorMessage = errorMessage;
        this.resultJson = resultJson;
        this.completedAt = Instant.now();
    }
}
