package com.mssecuritycodeanalysis.domain.model.evaluacion;

import java.util.Map;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisHibrido;

public record ResultadoCasoExperimental(CasoExperimental caso, ResultadoAnalisisHibrido resultadosOriginales,
        Map<Metodo, ClasificacionMetodo> clasificaciones, long tiempoMilisegundos, String falloTecnico) {
    public ResultadoCasoExperimental { clasificaciones = Map.copyOf(clasificaciones); }
    public boolean comparable() {
        return falloTecnico == null && clasificaciones.size() == Metodo.values().length
                && clasificaciones.values().stream().noneMatch(valor -> valor.clasificacion() == Clasificacion.NO_EVALUABLE);
    }
    public enum Metodo { ESTATICO, IA, HIBRIDO }
    public enum Clasificacion { VP, VN, FP, FN, NO_EVALUABLE }
    public record ClasificacionMetodo(Clasificacion clasificacion, String motivo,
            int hallazgosCategoria, int hallazgosCorrespondientes, int hallazgosComplementarios,
            long tiempoMilisegundos) { }
}
