package com.mssecuritycodeanalysis.evaluacion;

import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mssecuritycodeanalysis.domain.model.*;
import com.mssecuritycodeanalysis.domain.model.evaluacion.*;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisHibrido.*;

public final class DatosEvaluacion {
    public static final String RUTA = "src/muestra/Unidad.java";
    public static final ObjectMapper MAPPER = new ObjectMapper().findAndRegisterModules();
    public static CasoExperimental caso(String id, boolean vulnerable) {
        return new CasoExperimental(id, "original.java", "preparado.java", "caso.zip", RUTA, "entrada",
                "CWE-23", "CWE-22", vulnerable ? CasoExperimental.ClasificacionEsperada.VULNERABLE : CasoExperimental.ClasificacionEsperada.SEGURO,
                vulnerable ? List.of(3) : List.of(), vulnerable ? List.of(5) : List.of(), List.of(),
                "origen", "preparado", "zip", "grupo", Map.of());
    }
    public static HallazgoSeguridad hallazgo(String cwe, String ruta, int linea) {
        return new HallazgoSeguridad("regla", "Indicio", List.of(cwe), ruta, linea, "ALTO", "ESTATICO");
    }
    public static ResultadoAnalisisEstatico estatico(List<HallazgoSeguridad> hallazgos) {
        return new ResultadoAnalisisEstatico(hallazgos, List.of("Java"), List.of("Java"), List.of(), List.of(RUTA), "version-simulada", "reglas-simuladas");
    }
    public static ResultadoAnalisisIA ia(List<HallazgoSeguridad> hallazgos) {
        return new ResultadoAnalisisIA("COMPLETADO", hallazgos, List.of(RUTA), List.of("Java"), List.of("Java"), List.of(),
                "qwen2.5-coder:7b-instruct", "digest-simulado", null, "prompt-simulado", "huella-simulada", "IA", List.of(), List.of());
    }
    public static ResultadoAnalisisHibrido resultado(List<HallazgoSeguridad> hallazgos, boolean falloIA) {
        CoberturaAnalizador cobertura = new CoberturaAnalizador(List.of("Java"), List.of("Java"), List.of(), List.of(), List.of(RUTA), List.of());
        ResultadoMetodo<ResultadoAnalisisEstatico> estatico = new ResultadoMetodo<>("COMPLETADO", estatico(hallazgos), null, null, 10, cobertura);
        ResultadoMetodo<ResultadoAnalisisIA> ia = new ResultadoMetodo<>(falloIA ? "ERROR" : "COMPLETADO", falloIA ? null : ia(hallazgos),
                falloIA ? "TIEMPO_AGOTADO" : null, falloIA ? "Sin respuesta" : null, 20, cobertura);
        List<HallazgoHibrido> hibridos = hallazgos.stream().map(h -> new HallazgoHibrido("h1", h.rutaRelativa(), h.cwe().getFirst(),
                h.linea(), h.descripcion(), h.nivelRiesgo(), HallazgoHibrido.Procedencia.AMBOS,
                HallazgoHibrido.EstadoCorrelacion.MISMA_OPERACION, HallazgoHibrido.EstadoRevision.PENDIENTE_REVISION,
                "Revision pendiente", List.of(), List.of(h))).toList();
        return new ResultadoAnalisisHibrido(falloIA ? "PARCIAL" : "COMPLETADO", estatico, ia, hibridos,
                List.of(RUTA), List.of(RUTA), new TiemposEjecucion(1, 10, 20, 1, 32, false), "version", List.of(), List.of());
    }
    private DatosEvaluacion() { }
}
