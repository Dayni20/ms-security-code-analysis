package com.mssecuritycodeanalysis.domain.model;

import java.util.List;

public record ResultadoAnalisisIA(String estado, List<HallazgoSeguridad> hallazgos,
        List<String> archivosAnalizados, List<String> lenguajesReconocidos,
        List<String> lenguajesConCobertura, List<String> lenguajesSinCobertura,
        String modelo, String digestModelo, ParametrosGeneracion parametros,
        String versionPrompt, String huellaPrompt, String metodoDeteccion,
        List<DetalleFragmento> fragmentos, List<String> limitaciones) {

    public ResultadoAnalisisIA {
        hallazgos = List.copyOf(hallazgos);
        archivosAnalizados = List.copyOf(archivosAnalizados);
        lenguajesReconocidos = List.copyOf(lenguajesReconocidos);
        lenguajesConCobertura = List.copyOf(lenguajesConCobertura);
        lenguajesSinCobertura = List.copyOf(lenguajesSinCobertura);
        fragmentos = List.copyOf(fragmentos);
        limitaciones = List.copyOf(limitaciones);
    }

    public record ParametrosGeneracion(double temperatura, int contexto, int maxTokensGeneracion,
            long semilla, int maxLineasFragmento, int maxCaracteresFragmento,
            int lineasSolapamiento, int margenTokens, int maxFragmentosPorArchivo) {
    }

    public record DetalleFragmento(String rutaRelativa, int lineaInicio, int lineaFin,
            String estado, String motivo, String descripcion, String huellaSolicitud) {
    }
}
