package com.caligo.backend.recon;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface ToolExecutionJobRepository extends JpaRepository<ToolExecutionJob, UUID> {

    List<ToolExecutionJob> findByUsernameAndToolOrderByCreatedAtDesc(String username, String tool, Pageable pageable);

    List<ToolExecutionJob> findByUsernameAndToolAndStatusOrderByCreatedAtDesc(String username, String tool, String status, Pageable pageable);
}
