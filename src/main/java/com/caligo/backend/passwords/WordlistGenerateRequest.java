package com.caligo.backend.passwords;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Size;

public record WordlistGenerateRequest(
        @Min(1) @Max(8) Integer minLength,
        @Min(1) @Max(8) Integer maxLength,
        @Size(max = 160) String charset,
        @Size(max = 80) String outputName,
        @Size(max = 500) String url,
        @Min(1) @Max(5) Integer depth,
        @Min(3) @Max(12) Integer minWordLength,
        Boolean withNumbers
) {
}
