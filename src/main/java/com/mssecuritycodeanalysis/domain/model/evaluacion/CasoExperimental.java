package com.mssecuritycodeanalysis.domain.model.evaluacion;

import java.util.List;
import java.util.Map;

public record CasoExperimental(String identificador, String archivoOriginal, String archivoPreparado,
        String paqueteAnalisis, String rutaAnalizada, String metodoOriginal, String cweOriginal,
        String cweNormalizado, ClasificacionEsperada clasificacionEsperada, List<Integer> lineasReferencia,
        List<Integer> lineasOperacion, List<Correspondencia> correspondenciaLineas,
        String sha256Original, String sha256Preparado, String sha256PaqueteAnalisis, String grupoOrigen,
        Map<String, String> archivosPermitidos) {
    public CasoExperimental {
        lineasReferencia = List.copyOf(lineasReferencia);
        lineasOperacion = List.copyOf(lineasOperacion);
        correspondenciaLineas = List.copyOf(correspondenciaLineas);
        archivosPermitidos = Map.copyOf(archivosPermitidos);
    }
    public enum ClasificacionEsperada { VULNERABLE, SEGURO }
    public record Correspondencia(int original, int preparada) { }
}
