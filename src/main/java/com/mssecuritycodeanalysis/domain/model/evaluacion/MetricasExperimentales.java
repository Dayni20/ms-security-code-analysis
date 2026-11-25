package com.mssecuritycodeanalysis.domain.model.evaluacion;

import java.util.Collection;
import com.mssecuritycodeanalysis.domain.model.evaluacion.ResultadoCasoExperimental.Clasificacion;

public record MetricasExperimentales(long total, long verdaderosPositivos, long verdaderosNegativos,
        long falsosPositivos, long falsosNegativos, Double precision, Double recall, Double f1) {
    public static MetricasExperimentales calcular(Collection<Clasificacion> resultados) {
        long vp = contar(resultados, Clasificacion.VP);
        long vn = contar(resultados, Clasificacion.VN);
        long fp = contar(resultados, Clasificacion.FP);
        long fn = contar(resultados, Clasificacion.FN);
        return new MetricasExperimentales(vp + vn + fp + fn, vp, vn, fp, fn,
                dividir(vp, vp + fp), dividir(vp, vp + fn), dividir(2 * vp, 2 * vp + fp + fn));
    }
    private static long contar(Collection<Clasificacion> resultados, Clasificacion buscada) {
        return resultados.stream().filter(buscada::equals).count();
    }
    private static Double dividir(long numerador, long denominador) {
        return denominador == 0 ? null : (double) numerador / denominador;
    }
}
