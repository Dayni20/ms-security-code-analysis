package com.mssecuritycodeanalysis.infrastructure.adapter.in.rest.excepcion;

import java.util.Map;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionEvaluacion;
import com.mssecuritycodeanalysis.infrastructure.adapter.in.rest.ControladorEvaluacionExperimental;

@RestControllerAdvice(assignableTypes = ControladorEvaluacionExperimental.class)
public class ManejadorErroresEvaluacion {
    @ExceptionHandler(ExcepcionEvaluacion.class)
    public ResponseEntity<Map<String, String>> manejar(ExcepcionEvaluacion excepcion) {
        HttpStatus estado = switch (excepcion.motivo()) {
            case SOLICITUD_INVALIDA -> HttpStatus.BAD_REQUEST;
            case NO_ENCONTRADO -> HttpStatus.NOT_FOUND;
            case OCUPADO, NO_FINALIZADA -> HttpStatus.CONFLICT;
            case CATALOGO_INVALIDO, ALMACENAMIENTO -> HttpStatus.INTERNAL_SERVER_ERROR;
        };
        return ResponseEntity.status(estado).body(Map.of("error", excepcion.getMessage(), "motivo", excepcion.motivo().name()));
    }
    @ExceptionHandler({HttpMessageNotReadableException.class, MethodArgumentTypeMismatchException.class})
    public ResponseEntity<Map<String, String>> solicitudInvalida() {
        return ResponseEntity.badRequest().body(Map.of("error", "Solicitud o identificador de evaluacion no valido"));
    }
}
