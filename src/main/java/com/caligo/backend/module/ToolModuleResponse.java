package com.caligo.backend.module;

import java.util.UUID;

public record ToolModuleResponse(
        UUID id,
        String code,
        String displayName,
        String description,
        boolean enabled
) {

    public static ToolModuleResponse from(ToolModule module) {
        return new ToolModuleResponse(
                module.getId(),
                module.getCode(),
                module.getDisplayName(),
                module.getDescription(),
                module.isEnabled()
        );
    }
}

