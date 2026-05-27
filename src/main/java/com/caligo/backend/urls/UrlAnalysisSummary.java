package com.caligo.backend.urls;

import java.time.Instant;
import java.util.UUID;

public record UrlAnalysisSummary(
        UUID id,
        String inputTarget,
        String normalizedUrl,
        String host,
        String mode,
        int riskScore,
        String verdict,
        boolean privateNetworkAllowed,
        int durationMs,
        Instant createdAt
) {
    static UrlAnalysisSummary from(UrlAnalysis analysis) {
        return new UrlAnalysisSummary(
                analysis.getId(),
                analysis.getInputTarget(),
                analysis.getNormalizedUrl(),
                analysis.getHost(),
                analysis.getMode(),
                analysis.getRiskScore(),
                analysis.getVerdict(),
                analysis.isPrivateNetworkAllowed(),
                analysis.getDurationMs(),
                analysis.getCreatedAt()
        );
    }
}
