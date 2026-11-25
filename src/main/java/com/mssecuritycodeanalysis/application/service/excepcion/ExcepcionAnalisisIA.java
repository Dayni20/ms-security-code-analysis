package com.mssecuritycodeanalysis.application.service.excepcion;

import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisIA;

public class ExcepcionAnalisisIA extends RuntimeException {

    public enum Motivo {
        NO_DISPONIBLE, MODELO_NO_ENCONTRADO, TIEMPO_AGOTADO, RESPUESTA_INVALIDA,
        GENERACION_INCOMPLETA, SIN_COBERTURA, FRAGMENTACION_INVALIDA, COMUNICACION_FALLIDA
    }

    private final Motivo motivo;
    private final ResultadoAnalisisIA resultadoParcial;

    public ExcepcionAnalisisIA(String mensaje, Motivo motivo) {
        this(mensaje, motivo, null, null);
    }

    public ExcepcionAnalisisIA(String mensaje, Motivo motivo, Throwable causa) {
        this(mensaje, motivo, causa, null);
    }

    public ExcepcionAnalisisIA(String mensaje, Motivo motivo, Throwable causa, ResultadoAnalisisIA resultadoParcial) {
        super(mensaje, causa);
        this.motivo = motivo;
        this.resultadoParcial = resultadoParcial;
    }

    public Motivo motivo() {
        return motivo;
    }

    public ResultadoAnalisisIA resultadoParcial() {
        return resultadoParcial;
    }
}
