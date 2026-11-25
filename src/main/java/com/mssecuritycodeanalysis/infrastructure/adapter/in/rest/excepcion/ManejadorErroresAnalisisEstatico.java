package com.mssecuritycodeanalysis.infrastructure.adapter.in.rest.excepcion;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisEstatico;
import com.mssecuritycodeanalysis.domain.Constantes;

@RestControllerAdvice
public class ManejadorErroresAnalisisEstatico {

    @ExceptionHandler(ExcepcionAnalisisEstatico.class)
    public ResponseEntity<Map<String, String>> analisisFallido(ExcepcionAnalisisEstatico excepcion) {
        HttpStatus estado = switch (excepcion.motivo()) {
            case NO_DISPONIBLE -> HttpStatus.SERVICE_UNAVAILABLE;
            case TIEMPO_AGOTADO -> HttpStatus.GATEWAY_TIMEOUT;
            case SIN_COBERTURA -> HttpStatus.UNPROCESSABLE_ENTITY;
            case EJECUCION_FALLIDA, SALIDA_INVALIDA -> HttpStatus.BAD_GATEWAY;
            case CONFIGURACION_INVALIDA, LIMPIEZA_FALLIDA -> HttpStatus.INTERNAL_SERVER_ERROR;
        };
        return ResponseEntity.status(estado).body(Map.of(Constantes.CLAVE_ERROR, excepcion.getMessage(),
                Constantes.CLAVE_MOTIVO, excepcion.motivo().name()));
    }
}
