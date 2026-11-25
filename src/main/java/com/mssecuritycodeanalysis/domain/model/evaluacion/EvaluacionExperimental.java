package com.mssecuritycodeanalysis.domain.model.evaluacion;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import com.mssecuritycodeanalysis.domain.model.evaluacion.ResultadoCasoExperimental.Metodo;

public record EvaluacionExperimental(UUID identificador, Estado estado, Instant fechaInicio,
        Instant fechaFinalizacion, List<CasoExperimental> casosSolicitados,
        List<ResultadoCasoExperimental> resultados, Map<String, String> reproducibilidad, String error) {
    public EvaluacionExperimental {
        casosSolicitados = List.copyOf(casosSolicitados);
        resultados = List.copyOf(resultados);
        reproducibilidad = Map.copyOf(reproducibilidad);
    }
    public enum Estado {
        PENDIENTE, EN_PROCESO, COMPLETADA, COMPLETADA_CON_ERRORES, FALLIDA, INTERRUMPIDA;
        public boolean finalizado() { return this != PENDIENTE && this != EN_PROCESO; }
    }
    public long duracionMilisegundos() {
        return Math.max(0, java.time.Duration.between(fechaInicio,
                fechaFinalizacion == null ? Instant.now() : fechaFinalizacion).toMillis());
    }
    public Resumen resumen() {
        int procesados = resultados.size();
        int exitosos = (int) resultados.stream().filter(ResultadoCasoExperimental::comparable).count();
        return new Resumen(identificador, estado, fechaInicio, fechaFinalizacion, duracionMilisegundos(),
                casosSolicitados.size(), procesados, exitosos, procesados - exitosos,
                casosSolicitados.size() - exitosos, porcentaje(procesados), porcentaje(exitosos),
                casosSolicitados.stream().map(CasoExperimental::identificador).toList(), excluidos(),
                metricas(false), metricas(true), reproducibilidad, error);
    }
    private List<String> excluidos() {
        java.util.Set<String> comparables = resultados.stream().filter(ResultadoCasoExperimental::comparable)
                .map(resultado -> resultado.caso().identificador()).collect(java.util.stream.Collectors.toSet());
        return casosSolicitados.stream().map(CasoExperimental::identificador).filter(id -> !comparables.contains(id)).toList();
    }
    private double porcentaje(int cantidad) {
        return casosSolicitados.isEmpty() ? 0 : 100.0 * cantidad / casosSolicitados.size();
    }
    private Map<Metodo, Map<String, MetricasExperimentales>> metricas(boolean individuales) {
        Map<Metodo, Map<String, MetricasExperimentales>> comparacion = new java.util.EnumMap<>(Metodo.class);
        for (Metodo metodo : Metodo.values()) {
            Map<String, MetricasExperimentales> categorias = new java.util.LinkedHashMap<>();
            for (String cwe : List.of("GLOBAL", "CWE-89", "CWE-78", "CWE-22")) {
                List<ResultadoCasoExperimental.Clasificacion> valores = resultados.stream()
                        .filter(caso -> individuales || caso.comparable())
                        .filter(caso -> cwe.equals("GLOBAL") || cwe.equals(caso.caso().cweNormalizado()))
                        .map(caso -> caso.clasificaciones().get(metodo))
                        .filter(java.util.Objects::nonNull).map(ResultadoCasoExperimental.ClasificacionMetodo::clasificacion).toList();
                categorias.put(cwe, MetricasExperimentales.calcular(valores));
            }
            comparacion.put(metodo, Map.copyOf(categorias));
        }
        return Map.copyOf(comparacion);
    }
    public record Resumen(UUID identificador, Estado estado, Instant fechaInicio, Instant fechaFinalizacion,
            long duracionMilisegundos, int casosSolicitados, int casosProcesados, int casosExitosos,
            int casosFallidos, int casosExcluidosComparacion, double porcentajeAvance, double coberturaExperimental,
            List<String> identificadoresSeleccionados, List<String> identificadoresExcluidosComparacion,
            Map<Metodo, Map<String, MetricasExperimentales>> comparacionPrincipal,
            Map<Metodo, Map<String, MetricasExperimentales>> resultadosDisponiblesPorMetodo,
            Map<String, String> reproducibilidad, String error) { }
}
