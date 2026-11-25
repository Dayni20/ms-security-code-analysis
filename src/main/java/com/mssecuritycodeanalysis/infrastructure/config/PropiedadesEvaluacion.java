package com.mssecuritycodeanalysis.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;
import jakarta.validation.constraints.NotBlank;

@Validated
@ConfigurationProperties(prefix = "evaluacion")
public record PropiedadesEvaluacion(@NotBlank String raizProyecto, @NotBlank String catalogo,
        @NotBlank String directorioResultados, @NotBlank String modelo) { }
