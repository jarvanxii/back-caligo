package com.caligo.backend.passwords;

import jakarta.validation.constraints.Size;

public record PasswordCrackRequest(
        @Size(max = 80_000) String hashes,
        @Size(max = 80) String hashFormat,
        @Size(max = 24) String hashcatMode,
        @Size(max = 24) String attackMode,
        @Size(max = 320) String wordlistFile,
        @Size(max = 80_000) String wordlistText,
        @Size(max = 80) String mask,
        Boolean usernameFormat,
        Boolean showPasswords
) {
}
