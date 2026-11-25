package com.mssecuritycodeanalysis.domain.model;

import java.util.List;

public record HallazgoHibrido(String identificador, String rutaRelativa, String cwe, int linea,
        String descripcion, String nivelRiesgo, Procedencia metodoDeteccion,
        EstadoCorrelacion estadoCorrelacion, EstadoRevision estadoRevision,
        String justificacion, List<Evidencia> evidencia, List<HallazgoSeguridad> originales) {

    public HallazgoHibrido {
        evidencia = List.copyOf(evidencia);
        originales = List.copyOf(originales);
    }

    public enum Procedencia { ESTATICO, IA, AMBOS }
    public enum EstadoCorrelacion { MISMA_OPERACION, SOLO_ESTATICO, SOLO_IA, AMBIGUA, NO_COMPARABLE }
    public enum EstadoRevision { RESPALDADO_POR_EVIDENCIA, DESCARTADO_CON_JUSTIFICACION, PENDIENTE_REVISION }
    public enum TipoEvidencia { ORIGEN, PROPAGACION, PROTECCION, OPERACION }

    public record Evidencia(TipoEvidencia tipo, int lineaInicio, int lineaFin, String descripcion) {
    }
}
