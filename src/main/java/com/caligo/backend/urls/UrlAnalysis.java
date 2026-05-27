package com.caligo.backend.urls;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "url_analysis_jobs")
public class UrlAnalysis {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(length = 36)
    private UUID id;

    @Column(length = 80)
    private String username;

    @Column(name = "input_target", nullable = false, length = 1000)
    private String inputTarget;

    @Column(name = "normalized_url", nullable = false, length = 1200)
    private String normalizedUrl;

    @Column(nullable = false, length = 255)
    private String host;

    @Column(nullable = false, length = 40)
    private String mode;

    @Column(name = "risk_score", nullable = false)
    private int riskScore;

    @Column(nullable = false, length = 80)
    private String verdict;

    @Column(name = "private_network_allowed", nullable = false)
    private boolean privateNetworkAllowed;

    @Column(name = "duration_ms", nullable = false)
    private int durationMs;

    @Column(name = "result_json", nullable = false, columnDefinition = "text")
    private String resultJson;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected UrlAnalysis() {
    }

    public UrlAnalysis(
            String username,
            String inputTarget,
            String normalizedUrl,
            String host,
            String mode,
            int riskScore,
            String verdict,
            boolean privateNetworkAllowed,
            int durationMs,
            String resultJson
    ) {
        this.username = username;
        this.inputTarget = inputTarget;
        this.normalizedUrl = normalizedUrl;
        this.host = host;
        this.mode = mode;
        this.riskScore = riskScore;
        this.verdict = verdict;
        this.privateNetworkAllowed = privateNetworkAllowed;
        this.durationMs = durationMs;
        this.resultJson = resultJson;
    }

    @PrePersist
    void onCreate() {
        createdAt = Instant.now();
    }

    public UUID getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getInputTarget() {
        return inputTarget;
    }

    public String getNormalizedUrl() {
        return normalizedUrl;
    }

    public String getHost() {
        return host;
    }

    public String getMode() {
        return mode;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public String getVerdict() {
        return verdict;
    }

    public boolean isPrivateNetworkAllowed() {
        return privateNetworkAllowed;
    }

    public int getDurationMs() {
        return durationMs;
    }

    public String getResultJson() {
        return resultJson;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
