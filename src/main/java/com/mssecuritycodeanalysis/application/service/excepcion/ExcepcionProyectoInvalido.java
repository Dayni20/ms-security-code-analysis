package com.mssecuritycodeanalysis.application.service.excepcion;

public class ExcepcionProyectoInvalido extends RuntimeException {

    public enum Motivo { ARCHIVO_INVALIDO, LIMITE_EXCEDIDO }

    private final Motivo motivo;

    public ExcepcionProyectoInvalido(String mensaje) {
        this(mensaje, Motivo.ARCHIVO_INVALIDO);
    }

    public ExcepcionProyectoInvalido(String mensaje, Motivo motivo) {
        super(mensaje);
        this.motivo = motivo;
    }

    public Motivo motivo() {
        return motivo;
    }
}
