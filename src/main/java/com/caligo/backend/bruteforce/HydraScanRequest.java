package com.caligo.backend.bruteforce;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record HydraScanRequest(
        @NotBlank @Size(max = 180) String target,
        @NotBlank @Size(max = 48) String service,
        @Min(1) @Max(65535) Integer port,
        Boolean ssl,

        @Size(max = 24) String usernameMode,
        @Size(max = 160) String username,
        @Size(max = 6000) String usernames,
        @Size(max = 320) String usernameFile,

        @Size(max = 24) String passwordMode,
        @Size(max = 240) String password,
        @Size(max = 10000) String passwords,
        @Size(max = 320) String passwordFile,
        @Size(max = 320) String comboFile,

        @Min(1) @Max(64) Integer tasks,
        @Min(3) @Max(300) Integer connectTimeoutSeconds,
        @Min(1) @Max(120) Integer responseWaitSeconds,
        Boolean stopOnFound,
        Boolean exitOnFirstHost,
        Boolean loopUsers,
        Boolean verboseAttempts,
        Boolean debugVerbose,

        @Size(max = 220) String httpPath,
        @Size(max = 1000) String httpParameters,
        @Size(max = 260) String httpFailCondition,
        @Size(max = 260) String httpSuccessCondition,
        @Size(max = 1000) String moduleOptions
) {
}
