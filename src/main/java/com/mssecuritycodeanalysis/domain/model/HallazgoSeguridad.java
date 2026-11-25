package com.mssecuritycodeanalysis.domain.model;

import java.util.List;

public record HallazgoSeguridad(String identificadorRegla, String descripcion, List<String> cwe,
        String rutaRelativa, int linea, String nivelRiesgo, String metodoDeteccion) {

    public HallazgoSeguridad {
        cwe = List.copyOf(cwe);
    }
}
