package com.mssecuritycodeanalysis.domain.model;

import java.util.List;

public record ResultadoAnalisisHibrido(String estado,
        ResultadoMetodo<ResultadoAnalisisEstatico> estatico, ResultadoMetodo<ResultadoAnalisisIA> ia,
        List<HallazgoHibrido> hallazgos, List<String> archivosRecibidos, List<String> archivosAnalizados,
        TiemposEjecucion tiempos, String versionCorrelacion, List<String> criterios, List<String> limitaciones) {

    public ResultadoAnalisisHibrido {
        hallazgos = List.copyOf(hallazgos);
        archivosRecibidos = List.copyOf(archivosRecibidos);
        archivosAnalizados = List.copyOf(archivosAnalizados);
        criterios = List.copyOf(criterios);
        limitaciones = List.copyOf(limitaciones);
    }

    public record ResultadoMetodo<T>(String estado, T resultado, String motivo, String error,
            long tiempoMilisegundos, CoberturaAnalizador cobertura) {
    }

    public record CoberturaAnalizador(List<String> lenguajesReconocidos, List<String> lenguajesConCobertura,
            List<String> lenguajesSinCobertura, List<String> lenguajesSinVerificar,
            List<String> archivosAnalizados, List<String> archivosNoAnalizados) {
        public CoberturaAnalizador {
            lenguajesReconocidos = List.copyOf(lenguajesReconocidos);
            lenguajesConCobertura = List.copyOf(lenguajesConCobertura);
            lenguajesSinCobertura = List.copyOf(lenguajesSinCobertura);
            lenguajesSinVerificar = List.copyOf(lenguajesSinVerificar);
            archivosAnalizados = List.copyOf(archivosAnalizados);
            archivosNoAnalizados = List.copyOf(archivosNoAnalizados);
        }
    }

    public record TiemposEjecucion(long cargaMilisegundos, long estaticoMilisegundos,
            long iaMilisegundos, long correlacionMilisegundos, long totalMilisegundos, boolean concurrente) {
    }
}
