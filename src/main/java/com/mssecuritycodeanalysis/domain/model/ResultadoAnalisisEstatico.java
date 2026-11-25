package com.mssecuritycodeanalysis.domain.model;

import java.util.List;

public record ResultadoAnalisisEstatico(List<HallazgoSeguridad> hallazgos,
        List<String> lenguajesReconocidos, List<String> lenguajesConReglas, List<String> lenguajesSinReglas,
        List<String> archivosAnalizados, String versionSemgrep, String huellaReglas) {

    public ResultadoAnalisisEstatico {
        hallazgos = List.copyOf(hallazgos);
        lenguajesReconocidos = List.copyOf(lenguajesReconocidos);
        lenguajesConReglas = List.copyOf(lenguajesConReglas);
        lenguajesSinReglas = List.copyOf(lenguajesSinReglas);
        archivosAnalizados = List.copyOf(archivosAnalizados);
    }
}
