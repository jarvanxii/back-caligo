package com.caligo.backend.vulnerabilities;

import jakarta.validation.constraints.Size;

public record SqlmapScanRequest(
        @Size(max = 500, message = "El objetivo es demasiado largo")
        String target,
        @Size(max = 2000, message = "Los datos POST son demasiado largos")
        String data,
        @Size(max = 2000, message = "La cookie es demasiado larga")
        String cookie,
        @Size(max = 80, message = "El parametro es demasiado largo")
        String parameter,
        Integer level,
        Integer risk,
        Integer threads,
        @Size(max = 8, message = "La tecnica es demasiado larga")
        String technique,
        @Size(max = 40, message = "El DBMS es demasiado largo")
        String dbms,
        Boolean forms,
        Boolean crawl,
        Boolean smart
) {
}
