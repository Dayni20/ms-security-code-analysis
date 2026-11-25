package com.mssecuritycodeanalysis.domain.service;

import java.util.List;
import java.util.Map;
import java.util.Locale;
import java.util.function.Predicate;
import com.mssecuritycodeanalysis.domain.model.*;
import com.mssecuritycodeanalysis.domain.model.evaluacion.*;
import com.mssecuritycodeanalysis.domain.model.evaluacion.ResultadoCasoExperimental.*;

public class EvaluadorCasoExperimental {
    public static final String POLITICA = "caso-cwe-ubicacion-v1: CWE normalizada y archivo exacto; "
            + "linea exacta del manifiesto mapeado o de la operacion vulnerable; sin tolerancia por proximidad. "
            + "Hibrido: indicios respaldados y pendientes; descartados no cuentan como positivos. "
            + "Otras ubicaciones, archivos y categorias se conservan como informacion complementaria. "
            + "Comparacion principal: interseccion de casos completos de los tres metodos. "
            + "Metricas indefinidas: null; F1 = 2VP/(2VP+FP+FN).";

    public ResultadoCasoExperimental evaluar(CasoExperimental caso, ResultadoAnalisisHibrido resultado) {
        ClasificacionMetodo estatico = clasificar(caso, completo(resultado.estatico()),
                resultado.estatico().resultado() == null ? List.of() : resultado.estatico().resultado().hallazgos(),
                resultado.estatico().tiempoMilisegundos(), detalle(resultado.estatico()));
        ClasificacionMetodo ia = clasificar(caso, completo(resultado.ia()),
                resultado.ia().resultado() == null ? List.of() : resultado.ia().resultado().hallazgos(),
                resultado.ia().tiempoMilisegundos(), detalle(resultado.ia()));
        List<HallazgoSeguridad> activos = resultado.hallazgos().stream()
                .filter(hallazgo -> hallazgo.estadoRevision() != HallazgoHibrido.EstadoRevision.DESCARTADO_CON_JUSTIFICACION)
                .map(hallazgo -> new HallazgoSeguridad(hallazgo.identificador(), hallazgo.descripcion(),
                        List.of(hallazgo.cwe()), hallazgo.rutaRelativa(), hallazgo.linea(), hallazgo.nivelRiesgo(), "HIBRIDO"))
                .toList();
        ClasificacionMetodo hibrido = clasificar(caso, completo(resultado.estatico()) && completo(resultado.ia()),
                activos, resultado.tiempos().totalMilisegundos(), "Requiere ambos analisis completos");
        return new ResultadoCasoExperimental(caso, resultado,
                Map.of(Metodo.ESTATICO, estatico, Metodo.IA, ia, Metodo.HIBRIDO, hibrido),
                resultado.tiempos().totalMilisegundos(), null);
    }
    public ResultadoCasoExperimental fallido(CasoExperimental caso, String motivo, long tiempo) {
        ClasificacionMetodo fallo = new ClasificacionMetodo(Clasificacion.NO_EVALUABLE, motivo, 0, 0, 0, tiempo);
        return new ResultadoCasoExperimental(caso, null,
                Map.of(Metodo.ESTATICO, fallo, Metodo.IA, fallo, Metodo.HIBRIDO, fallo), tiempo, motivo);
    }
    private boolean completo(ResultadoAnalisisHibrido.ResultadoMetodo<?> metodo) {
        return metodo != null && metodo.resultado() != null && metodo.error() == null
                && "COMPLETADO".equals(metodo.estado());
    }
    private String detalle(ResultadoAnalisisHibrido.ResultadoMetodo<?> metodo) {
        return metodo == null ? "Resultado ausente" : String.join("; ",
                metodo.estado(), String.valueOf(metodo.motivo()), String.valueOf(metodo.error()));
    }
    private ClasificacionMetodo clasificar(CasoExperimental caso, boolean completo,
            List<HallazgoSeguridad> hallazgos, long tiempo, String error) {
        Predicate<HallazgoSeguridad> categoria = hallazgo -> mismaRuta(caso, hallazgo)
                && hallazgo.cwe().stream().map(EvaluadorCasoExperimental::normalizarCwe).anyMatch(caso.cweNormalizado()::equals);
        List<HallazgoSeguridad> candidatos = hallazgos.stream().filter(categoria).toList();
        long correspondientes = candidatos.stream().filter(hallazgo -> caso.lineasReferencia().contains(hallazgo.linea())
                || caso.lineasOperacion().contains(hallazgo.linea())).count();
        int complementarios = hallazgos.size() - (int) correspondientes;
        if (!completo) {
            return new ClasificacionMetodo(Clasificacion.NO_EVALUABLE, error, candidatos.size(),
                    (int) correspondientes, complementarios, tiempo);
        }
        boolean vulnerable = caso.clasificacionEsperada() == CasoExperimental.ClasificacionEsperada.VULNERABLE;
        Clasificacion clasificacion = vulnerable ? (correspondientes > 0 ? Clasificacion.VP : Clasificacion.FN)
                : (candidatos.isEmpty() ? Clasificacion.VN : Clasificacion.FP);
        return new ClasificacionMetodo(clasificacion, "Politica caso-cwe-ubicacion-v1", candidatos.size(),
                (int) correspondientes, vulnerable ? complementarios : hallazgos.size() - candidatos.size(), tiempo);
    }
    private boolean mismaRuta(CasoExperimental caso, HallazgoSeguridad hallazgo) {
        return CorrelacionadorHallazgos.normalizarRuta(caso.rutaAnalizada())
                .equals(CorrelacionadorHallazgos.normalizarRuta(hallazgo.rutaRelativa()));
    }
    public static String normalizarCwe(String cwe) {
        if (cwe == null) return "";
        String valor = cwe.toUpperCase(Locale.ROOT).trim();
        if (!valor.matches("CWE-0*[0-9]+")) return valor;
        String numero = valor.substring(4).replaceFirst("^0+(?!$)", "");
        return "CWE-" + (java.util.Set.of("23", "36").contains(numero) ? "22" : numero);
    }
}
