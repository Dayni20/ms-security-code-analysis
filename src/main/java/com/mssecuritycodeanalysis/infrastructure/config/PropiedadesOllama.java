package com.mssecuritycodeanalysis.infrastructure.config;

import java.net.URI;
import java.util.Locale;
import java.util.Set;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import com.mssecuritycodeanalysis.domain.Constantes;

@Validated
@ConfigurationProperties(prefix = Constantes.PREFIJO_CONFIGURACION_OLLAMA)
public record PropiedadesOllama(@NotNull URI url, @NotBlank String modelo,
        @DecimalMin(Constantes.TEMPERATURA_MINIMA_IA) @DecimalMax(Constantes.TEMPERATURA_MAXIMA_IA) double temperatura,
        @Min(1) int contexto, @Min(1) int maxTokensGeneracion, long semilla,
        @Min(1) int maxLineasFragmento, @Min(1) int maxCaracteresFragmento,
        @Min(0) int lineasSolapamiento, @Min(1) int margenTokens,
        @Min(1) int maxFragmentosPorArchivo,
        @Min(1) int timeoutConexionSegundos, @Min(1) int timeoutRespuestaSegundos,
        @Min(1) int maxBytesRespuesta, @NotEmpty Set<@NotBlank String> lenguajesAdmitidos,
        @DefaultValue(Constantes.PERMANENCIA_MODELO_PREDETERMINADA) @Min(0) int mantenerModeloSegundos) {

    @AssertTrue(message = Constantes.MENSAJE_CONFIGURACION_IA_INVALIDA)
    public boolean isConfiguracionValida() {
        if (url == null || url.getHost() == null) {
            return false;
        }
        boolean protocoloValido = Constantes.PROTOCOLO_HTTP.equalsIgnoreCase(url.getScheme())
                || Constantes.PROTOCOLO_HTTPS.equalsIgnoreCase(url.getScheme());
        boolean hostLocal = Constantes.HOSTS_OLLAMA_LOCALES.contains(url.getHost().toLowerCase(Locale.ROOT));
        boolean contextoValido = (long) maxTokensGeneracion + margenTokens < contexto;
        return protocoloValido && hostLocal && contextoValido && lineasSolapamiento < maxLineasFragmento;
    }
}
