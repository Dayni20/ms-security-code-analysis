package com.mssecuritycodeanalysis.infrastructure.config;

import java.nio.file.Path;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import com.mssecuritycodeanalysis.domain.Constantes;

@Validated
@ConfigurationProperties(prefix = Constantes.PREFIJO_CONFIGURACION_SEMGREP)
public record PropiedadesSemgrep(@NotBlank String ejecutable, @NotNull Path reglas,
        @Min(1) long tiempoMaximoSegundos, @Min(1) int maxBytesSalida,
        @NotNull ModoEjecucion modoEjecucion, @NotBlank String wslEjecutable,
        @NotBlank String wslDistribucion, @NotBlank String wslEjecutableSemgrep) {

    public enum ModoEjecucion {
        NATIVO, WSL
    }
}
