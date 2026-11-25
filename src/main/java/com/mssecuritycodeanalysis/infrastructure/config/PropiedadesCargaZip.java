package com.mssecuritycodeanalysis.infrastructure.config;

import java.nio.file.Path;
import java.util.Map;
import java.util.Set;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

import com.mssecuritycodeanalysis.domain.Constantes;

@Validated
@ConfigurationProperties(prefix = Constantes.PREFIJO_CONFIGURACION_CARGA)
public record PropiedadesCargaZip(
        @Min(1) long maxBytesZip,
        @Min(1) long maxBytesEntrada,
        @Min(1) long maxBytesDescomprimidos,
        @Min(1) int maxEntradas,
        @NotNull Path directorioTemporal,
        @NotEmpty Map<@Pattern(regexp = Constantes.PATRON_EXTENSION_PERMITIDA) String, @NotBlank String> lenguajesPorExtension,
        @NotNull Set<@NotBlank @Pattern(regexp = Constantes.PATRON_DIRECTORIO_EXCLUIDO) String> directoriosExcluidos) {
}
