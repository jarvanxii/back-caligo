package com.caligo.backend.module;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/modules")
public class ToolModuleController {

    private final ToolModuleRepository modules;

    public ToolModuleController(ToolModuleRepository modules) {
        this.modules = modules;
    }

    @GetMapping
    public List<ToolModuleResponse> list(@RequestParam(defaultValue = "true") boolean enabledOnly) {
        return (enabledOnly ? modules.findByEnabledTrueOrderByDisplayNameAsc() : modules.findAllByOrderByDisplayNameAsc())
                .stream()
                .map(ToolModuleResponse::from)
                .toList();
    }
}

