package com.mssecuritycodeanalysis.application.service.excepcion;

public class ExcepcionAnalisisEstatico extends RuntimeException {

    public enum Motivo {
        NO_DISPONIBLE, CONFIGURACION_INVALIDA, SIN_COBERTURA, TIEMPO_AGOTADO,
        EJECUCION_FALLIDA, SALIDA_INVALIDA, LIMPIEZA_FALLIDA
    }

    private final Motivo motivo;

    public ExcepcionAnalisisEstatico(String mensaje, Motivo motivo) {
        super(mensaje);
        this.motivo = motivo;
    }

    public ExcepcionAnalisisEstatico(String mensaje, Motivo motivo, Throwable causa) {
        super(mensaje, causa);
        this.motivo = motivo;
    }

    public Motivo motivo() {
        return motivo;
    }
}
