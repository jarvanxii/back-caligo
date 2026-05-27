package com.caligo.backend.urls;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface UrlAnalysisRepository extends JpaRepository<UrlAnalysis, UUID> {
    List<UrlAnalysis> findByUsernameOrderByCreatedAtDesc(String username, Pageable pageable);
}
