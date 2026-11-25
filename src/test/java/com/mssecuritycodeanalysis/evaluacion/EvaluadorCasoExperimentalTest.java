package com.mssecuritycodeanalysis.evaluacion;

import static org.assertj.core.api.Assertions.*;
import static com.mssecuritycodeanalysis.evaluacion.DatosEvaluacion.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import com.mssecuritycodeanalysis.domain.model.*;
import com.mssecuritycodeanalysis.domain.model.evaluacion.*;
import com.mssecuritycodeanalysis.domain.model.evaluacion.ResultadoCasoExperimental.*;
import com.mssecuritycodeanalysis.domain.service.EvaluadorCasoExperimental;

class EvaluadorCasoExperimentalTest {
    private final EvaluadorCasoExperimental evaluador = new EvaluadorCasoExperimental();
    @ParameterizedTest
    @CsvSource({"true,true,VP", "true,false,FN", "false,true,FP", "false,false,VN"})
    void clasificaPorCaso(boolean vulnerable, boolean detectado, Clasificacion esperada) {
        List<HallazgoSeguridad> hallazgos = detectado ? List.of(hallazgo("CWE-22", RUTA, 5)) : List.of();
        ResultadoCasoExperimental resultado = evaluador.evaluar(caso("CasoUno", vulnerable), resultado(hallazgos, false));
        for (ClasificacionMetodo metodo : resultado.clasificaciones().values()) assertThat(metodo.clasificacion()).isEqualTo(esperada);
    }
    @ParameterizedTest
    @CsvSource({"CWE-23,CWE-22", "CWE-36,CWE-22", "CWE-022,CWE-22", "CWE-089,CWE-89", "CWE-78,CWE-78"})
    void normalizaCategorias(String original, String normalizada) {
        assertThat(EvaluadorCasoExperimental.normalizarCwe(original)).isEqualTo(normalizada);
    }
    @Test
    void exigeUbicacionYConservaExtrasSinDuplicarConteos() {
        List<HallazgoSeguridad> hallazgos = List.of(hallazgo("CWE-23", RUTA, 5), hallazgo("CWE-23", RUTA, 5),
                hallazgo("CWE-22", RUTA, 8), hallazgo("CWE-89", RUTA, 5), hallazgo("CWE-22", "otro.java", 5));
        ResultadoCasoExperimental resultado = evaluador.evaluar(caso("CasoUno", true), resultado(hallazgos, false));
        assertThat(resultado.clasificaciones().get(Metodo.ESTATICO).clasificacion()).isEqualTo(Clasificacion.VP);
        assertThat(resultado.clasificaciones().get(Metodo.ESTATICO).hallazgosComplementarios()).isEqualTo(3);
        assertThat(resultado.resultadosOriginales().estatico().resultado().hallazgos()).hasSize(5);
        assertThat(MetricasExperimentales.calcular(List.of(resultado.clasificaciones().get(Metodo.ESTATICO).clasificacion())).verdaderosPositivos()).isEqualTo(1);
        ResultadoCasoExperimental incorrecto = evaluador.evaluar(caso("CasoUno", true), resultado(hallazgos.subList(2, 5), false));
        assertThat(incorrecto.clasificaciones().get(Metodo.ESTATICO).clasificacion()).isEqualTo(Clasificacion.FN);
    }
    @Test
    void admiteOrigenAnotadoYNoUsaToleranciaDeLineas() {
        assertThat(evaluador.evaluar(caso("Uno", true), resultado(List.of(hallazgo("CWE-22", RUTA, 3)), false))
                .clasificaciones().get(Metodo.IA).clasificacion()).isEqualTo(Clasificacion.VP);
        assertThat(evaluador.evaluar(caso("Uno", true), resultado(List.of(hallazgo("CWE-22", RUTA, 4)), false))
                .clasificaciones().get(Metodo.IA).clasificacion()).isEqualTo(Clasificacion.FN);
    }
    @Test
    void descartaIndiciosJustificadosSoloEnHibrido() {
        ResultadoAnalisisHibrido base = resultado(List.of(hallazgo("CWE-22", RUTA, 5)), false);
        HallazgoHibrido anterior = base.hallazgos().getFirst();
        HallazgoHibrido descartado = new HallazgoHibrido(anterior.identificador(), RUTA, "CWE-22", 5,
                anterior.descripcion(), anterior.nivelRiesgo(), anterior.metodoDeteccion(), anterior.estadoCorrelacion(),
                HallazgoHibrido.EstadoRevision.DESCARTADO_CON_JUSTIFICACION, "Proteccion comprobada", List.of(), anterior.originales());
        ResultadoAnalisisHibrido modificado = new ResultadoAnalisisHibrido(base.estado(), base.estatico(), base.ia(), List.of(descartado),
                base.archivosRecibidos(), base.archivosAnalizados(), base.tiempos(), base.versionCorrelacion(), base.criterios(), base.limitaciones());
        ResultadoCasoExperimental resultado = evaluador.evaluar(caso("Uno", false), modificado);
        assertThat(resultado.clasificaciones().get(Metodo.HIBRIDO).clasificacion()).isEqualTo(Clasificacion.VN);
        assertThat(resultado.clasificaciones().get(Metodo.IA).clasificacion()).isEqualTo(Clasificacion.FP);
        assertThat(resultado.resultadosOriginales().hallazgos()).containsExactly(descartado);
    }
    @Test
    void excluyeFallosDelConjuntoComunPeroConservaResultadosDisponibles() {
        ResultadoCasoExperimental completo = evaluador.evaluar(caso("Uno", true), resultado(List.of(hallazgo("CWE-22", RUTA, 5)), false));
        ResultadoCasoExperimental parcial = evaluador.evaluar(caso("Dos", false), resultado(List.of(), true));
        assertThat(parcial.clasificaciones().get(Metodo.IA).clasificacion()).isEqualTo(Clasificacion.NO_EVALUABLE);
        EvaluacionExperimental evaluacion = new EvaluacionExperimental(UUID.randomUUID(), EvaluacionExperimental.Estado.COMPLETADA_CON_ERRORES,
                Instant.now(), Instant.now(), List.of(completo.caso(), parcial.caso()), List.of(completo, parcial), Map.of(), null);
        EvaluacionExperimental.Resumen resumen = evaluacion.resumen();
        for (Metodo metodo : Metodo.values()) assertThat(resumen.comparacionPrincipal().get(metodo).get("GLOBAL").total()).isEqualTo(1);
        assertThat(resumen.resultadosDisponiblesPorMetodo().get(Metodo.ESTATICO).get("GLOBAL").total()).isEqualTo(2);
        assertThat(resumen.casosFallidos()).isEqualTo(1);
        assertThat(resumen.coberturaExperimental()).isEqualTo(50);
    }
    @Test
    void calculaMetricasYDivisionesIndefinidas() {
        MetricasExperimentales valores = MetricasExperimentales.calcular(List.of(Clasificacion.VP, Clasificacion.VP, Clasificacion.FP, Clasificacion.FN, Clasificacion.VN));
        assertThat(valores.total()).isEqualTo(5);
        assertThat(valores.precision()).isEqualTo(2.0 / 3);
        assertThat(valores.recall()).isEqualTo(2.0 / 3);
        assertThat(valores.f1()).isEqualTo(2.0 / 3);
        MetricasExperimentales vacio = MetricasExperimentales.calcular(List.of(Clasificacion.NO_EVALUABLE));
        assertThat(vacio.precision()).isNull(); assertThat(vacio.recall()).isNull(); assertThat(vacio.f1()).isNull();
        assertThat(MetricasExperimentales.calcular(List.of(Clasificacion.VN)).f1()).isNull();
        assertThat(MetricasExperimentales.calcular(List.of(Clasificacion.FN)).f1()).isZero();
    }
    @Test
    void globalSeCalculaDesdeConteosYNoDesdePromediosDeCategorias() {
        CasoExperimental base = caso("SQL", true);
        CasoExperimental sql = new CasoExperimental(base.identificador(), base.archivoOriginal(), base.archivoPreparado(),
                base.paqueteAnalisis(), base.rutaAnalizada(), base.metodoOriginal(), "CWE-89", "CWE-89",
                base.clasificacionEsperada(), base.lineasReferencia(), base.lineasOperacion(), base.correspondenciaLineas(),
                base.sha256Original(), base.sha256Preparado(), base.sha256PaqueteAnalisis(), base.grupoOrigen(), base.archivosPermitidos());
        ResultadoCasoExperimental vp = evaluador.evaluar(sql, resultado(List.of(hallazgo("CWE-89", RUTA, 5)), false));
        ResultadoCasoExperimental fp1 = evaluador.evaluar(caso("Uno", false), resultado(List.of(hallazgo("CWE-22", RUTA, 5)), false));
        ResultadoCasoExperimental fp2 = evaluador.evaluar(caso("Dos", false), resultado(List.of(hallazgo("CWE-22", RUTA, 5)), false));
        EvaluacionExperimental evaluacion = new EvaluacionExperimental(UUID.randomUUID(), EvaluacionExperimental.Estado.COMPLETADA,
                Instant.now(), Instant.now(), List.of(sql, fp1.caso(), fp2.caso()), List.of(vp, fp1, fp2), Map.of(), null);
        Map<String, MetricasExperimentales> metricas = evaluacion.resumen().comparacionPrincipal().get(Metodo.ESTATICO);
        assertThat(metricas.get("GLOBAL").precision()).isEqualTo(1.0 / 3);
        assertThat(metricas.get("CWE-89").precision()).isEqualTo(1);
        assertThat(metricas.get("CWE-22").precision()).isZero();
    }
    @Test
    void coberturaParcialNoSeInterpretaComoNegativo() {
        ResultadoAnalisisHibrido base = resultado(List.of(), false);
        var parcial = new ResultadoAnalisisHibrido.ResultadoMetodo<>("PARCIAL", base.ia().resultado(), "SIN_COBERTURA", null,
                20, base.ia().cobertura());
        ResultadoAnalisisHibrido modificado = new ResultadoAnalisisHibrido("PARCIAL", base.estatico(), parcial, base.hallazgos(),
                base.archivosRecibidos(), base.archivosAnalizados(), base.tiempos(), base.versionCorrelacion(), base.criterios(), base.limitaciones());
        ResultadoCasoExperimental resultado = evaluador.evaluar(caso("Uno", false), modificado);
        assertThat(resultado.comparable()).isFalse();
        assertThat(resultado.clasificaciones().get(Metodo.IA).clasificacion()).isEqualTo(Clasificacion.NO_EVALUABLE);
        assertThat(resultado.clasificaciones().get(Metodo.HIBRIDO).clasificacion()).isEqualTo(Clasificacion.NO_EVALUABLE);
    }

}
