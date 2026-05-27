package com.caligo.backend.module;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface ToolModuleRepository extends JpaRepository<ToolModule, UUID> {

    List<ToolModule> findByEnabledTrueOrderByDisplayNameAsc();

    List<ToolModule> findAllByOrderByDisplayNameAsc();
}

