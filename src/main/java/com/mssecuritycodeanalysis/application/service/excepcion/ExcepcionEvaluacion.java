package com.mssecuritycodeanalysis.application.service.excepcion;

public class ExcepcionEvaluacion extends RuntimeException {
    private final Motivo motivo;
    public ExcepcionEvaluacion(Motivo motivo, String mensaje) { super(mensaje); this.motivo = motivo; }
    public ExcepcionEvaluacion(Motivo motivo, String mensaje, Throwable causa) { super(mensaje, causa); this.motivo = motivo; }
    public Motivo motivo() { return motivo; }
    public enum Motivo { SOLICITUD_INVALIDA, NO_ENCONTRADO, OCUPADO, NO_FINALIZADA, CATALOGO_INVALIDO, ALMACENAMIENTO }
}
