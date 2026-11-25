package com.mssecuritycodeanalysis.infrastructure.adapter.in.rest.excepcion;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisIA;
import com.mssecuritycodeanalysis.domain.Constantes;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisIA;

@RestControllerAdvice
public class ManejadorErroresAnalisisIA {

    @ExceptionHandler(ExcepcionAnalisisIA.class)
    public ResponseEntity<RespuestaErrorIA> analisisFallido(ExcepcionAnalisisIA excepcion) {
        HttpStatus estado = switch (excepcion.motivo()) {
            case NO_DISPONIBLE, MODELO_NO_ENCONTRADO -> HttpStatus.SERVICE_UNAVAILABLE;
            case TIEMPO_AGOTADO -> HttpStatus.GATEWAY_TIMEOUT;
            case SIN_COBERTURA, FRAGMENTACION_INVALIDA -> HttpStatus.UNPROCESSABLE_ENTITY;
            case RESPUESTA_INVALIDA, GENERACION_INCOMPLETA, COMUNICACION_FALLIDA -> HttpStatus.BAD_GATEWAY;
        };
        return ResponseEntity.status(estado).body(new RespuestaErrorIA(Constantes.ESTADO_ANALISIS_INCOMPLETO,
                excepcion.getMessage(), excepcion.motivo().name(), excepcion.resultadoParcial()));
    }

    public record RespuestaErrorIA(String estado, String error, String motivo, ResultadoAnalisisIA resultado) {
    }
}
