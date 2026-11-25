package com.mssecuritycodeanalysis.infrastructure.adapter.in.rest;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import com.mssecuritycodeanalysis.domain.model.evaluacion.*;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisEstatico;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisIA;
import com.mssecuritycodeanalysis.domain.model.evaluacion.ResultadoCasoExperimental.Metodo;

public class ExportadorEvaluacionCsv {
    public byte[] exportar(EvaluacionExperimental evaluacion) {
        StringBuilder csv = new StringBuilder("\ufeff");
        fila(csv, "tipoRegistro", "ejecucion", "estadoEjecucion", "caso", "grupoOrigen", "cweOriginal", "cweNormalizado",
                "clasificacionEsperada", "metodo", "clasificacionObtenida", "incluidoComparacionPrincipal",
                "tiempoMilisegundos", "motivo", "sha256Zip", "hallazgosCategoria", "hallazgosCorrespondientes",
                "hallazgosComplementarios", "ambitoMetrica", "total", "VP", "VN", "FP", "FN", "precision", "recall", "F1",
                "versionSemgrep", "sha256Reglas", "modelo", "digestModelo", "versionPrompt", "sha256Prompt",
                "casosSolicitados", "casosProcesados", "casosExitosos", "casosFallidos", "casosExcluidosComparacion",
                "coberturaExperimental", "porcentajeAvance", "sha256Catalogo");
        for (ResultadoCasoExperimental resultado : evaluacion.resultados()) {
            for (Metodo metodo : Metodo.values()) filaCaso(csv, evaluacion, resultado, metodo);
        }
        agregarPendientes(csv, evaluacion);
        agregarMetricas(csv, evaluacion, "COMPARACION_PRINCIPAL", evaluacion.resumen().comparacionPrincipal());
        agregarMetricas(csv, evaluacion, "DISPONIBLES_POR_METODO", evaluacion.resumen().resultadosDisponiblesPorMetodo());
        return csv.toString().getBytes(StandardCharsets.UTF_8);
    }
    private void filaCaso(StringBuilder csv, EvaluacionExperimental evaluacion, ResultadoCasoExperimental resultado, Metodo metodo) {
        CasoExperimental caso = resultado.caso();
        ResultadoCasoExperimental.ClasificacionMetodo clasificacion = resultado.clasificaciones().get(metodo);
        List<Object> celdas = vacias();
        celdas.set(0, "CASO"); celdas.set(1, evaluacion.identificador()); celdas.set(2, evaluacion.estado());
        celdas.set(3, caso.identificador()); celdas.set(4, caso.grupoOrigen()); celdas.set(5, caso.cweOriginal());
        celdas.set(6, caso.cweNormalizado()); celdas.set(7, caso.clasificacionEsperada()); celdas.set(8, metodo);
        celdas.set(9, clasificacion.clasificacion()); celdas.set(10, resultado.comparable());
        celdas.set(11, clasificacion.tiempoMilisegundos()); celdas.set(12, clasificacion.motivo());
        celdas.set(13, caso.sha256PaqueteAnalisis()); celdas.set(14, clasificacion.hallazgosCategoria());
        celdas.set(15, clasificacion.hallazgosCorrespondientes()); celdas.set(16, clasificacion.hallazgosComplementarios());
        for (int indice = 26; indice < 32; indice++) celdas.set(indice, "NO_DISPONIBLE");
        if (resultado.resultadosOriginales() != null) {
            ResultadoAnalisisEstatico estatico = resultado.resultadosOriginales().estatico().resultado();
            ResultadoAnalisisIA ia = resultado.resultadosOriginales().ia().resultado();
            celdas.set(26, estatico == null ? "NO_DISPONIBLE" : estatico.versionSemgrep());
            celdas.set(27, estatico == null ? "NO_DISPONIBLE" : estatico.huellaReglas());
            celdas.set(28, ia == null ? "NO_DISPONIBLE" : ia.modelo());
            celdas.set(29, ia == null ? "NO_DISPONIBLE" : ia.digestModelo());
            celdas.set(30, ia == null ? "NO_DISPONIBLE" : ia.versionPrompt());
            celdas.set(31, ia == null ? "NO_DISPONIBLE" : ia.huellaPrompt());
        }
        datosEjecucion(celdas, evaluacion);
        fila(csv, celdas.toArray());
    }
    private void agregarMetricas(StringBuilder csv, EvaluacionExperimental evaluacion, String ambito,
            Map<Metodo, Map<String, MetricasExperimentales>> metricas) {
        for (Metodo metodo : Metodo.values()) {
            for (String cwe : List.of("GLOBAL", "CWE-89", "CWE-78", "CWE-22")) {
                MetricasExperimentales metrica = metricas.get(metodo).get(cwe);
                List<Object> celdas = vacias();
                celdas.set(0, "METRICA"); celdas.set(1, evaluacion.identificador()); celdas.set(2, evaluacion.estado());
                celdas.set(6, cwe); celdas.set(8, metodo); celdas.set(17, ambito); celdas.set(18, metrica.total());
                celdas.set(19, metrica.verdaderosPositivos()); celdas.set(20, metrica.verdaderosNegativos());
                celdas.set(21, metrica.falsosPositivos()); celdas.set(22, metrica.falsosNegativos());
                celdas.set(23, metrica.precision()); celdas.set(24, metrica.recall()); celdas.set(25, metrica.f1());
                datosEjecucion(celdas, evaluacion);
                fila(csv, celdas.toArray());
            }
        }
    }
    private void agregarPendientes(StringBuilder csv, EvaluacionExperimental evaluacion) {
        java.util.Set<String> procesados = evaluacion.resultados().stream().map(resultado -> resultado.caso().identificador())
                .collect(java.util.stream.Collectors.toSet());
        for (CasoExperimental caso : evaluacion.casosSolicitados()) {
            if (procesados.contains(caso.identificador())) continue;
            ResultadoCasoExperimental pendiente = new com.mssecuritycodeanalysis.domain.service.EvaluadorCasoExperimental()
                    .fallido(caso, "Caso no procesado: " + evaluacion.estado(), 0);
            for (Metodo metodo : Metodo.values()) filaCaso(csv, evaluacion, pendiente, metodo);
        }
    }
    private void datosEjecucion(List<Object> celdas, EvaluacionExperimental evaluacion) {
        EvaluacionExperimental.Resumen resumen = evaluacion.resumen();
        celdas.set(32, resumen.casosSolicitados()); celdas.set(33, resumen.casosProcesados());
        celdas.set(34, resumen.casosExitosos()); celdas.set(35, resumen.casosFallidos());
        celdas.set(36, resumen.casosExcluidosComparacion()); celdas.set(37, resumen.coberturaExperimental());
        celdas.set(38, resumen.porcentajeAvance()); celdas.set(39, resumen.reproducibilidad().get("sha256Catalogo"));
    }
    private List<Object> vacias() { return new ArrayList<>(java.util.Collections.nCopies(40, "")); }
    private void fila(StringBuilder csv, Object... valores) {
        for (int indice = 0; indice < valores.length; indice++) {
            if (indice > 0) csv.append(',');
            String valor = valores[indice] == null ? "NO_DISPONIBLE" : valores[indice].toString();
            String inicio = valor.stripLeading();
            if (!inicio.isEmpty() && "=+-@".indexOf(inicio.charAt(0)) >= 0) valor = "'" + valor;
            csv.append('"').append(valor.replace("\"", "\"\"")).append('"');
        }
        csv.append("\r\n");
    }
}
