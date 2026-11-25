package com.mssecuritycodeanalysis.domain.model;

import java.time.Instant;

public record InformeAnalisis(Metodo metodo, String nombreProyecto, String estado,
        Instant fechaAnalisisDeclarada, Instant fechaGeneracion, Long tiempoSolicitudMilisegundos, String motivo, String error,
        ResultadoAnalisisEstatico estatico, ResultadoAnalisisIA ia, ResultadoAnalisisHibrido hibrido) {
    public enum Metodo { ESTATICO, IA, HIBRIDO }
}
