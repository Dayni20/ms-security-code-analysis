package com.mssecuritycodeanalysis.infrastructure.adapter.in.rest.excepcion;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.MultipartException;
import org.springframework.web.multipart.support.MissingServletRequestPartException;

import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionProyectoInvalido.Motivo;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionProyectoInvalido;
import com.mssecuritycodeanalysis.domain.Constantes;

@RestControllerAdvice
public class ManejadorErroresCarga {

    @ExceptionHandler(ExcepcionProyectoInvalido.class)
    public ResponseEntity<Map<String, String>> proyectoInvalido(ExcepcionProyectoInvalido excepcion) {
        HttpStatus estado = excepcion.motivo() == Motivo.LIMITE_EXCEDIDO
                ? HttpStatus.PAYLOAD_TOO_LARGE : HttpStatus.BAD_REQUEST;
        return ResponseEntity.status(estado).body(Map.of(Constantes.CLAVE_ERROR, excepcion.getMessage()));
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<Map<String, String>> limiteMultipartExcedido() {
        return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
                .body(Map.of(Constantes.CLAVE_ERROR, Constantes.MENSAJE_LIMITE_MULTIPART));
    }

    @ExceptionHandler({MissingServletRequestPartException.class, MissingServletRequestParameterException.class,
            MultipartException.class})
    public ResponseEntity<Map<String, String>> archivoFaltanteOInvalido() {
        return ResponseEntity.badRequest().body(Map.of(Constantes.CLAVE_ERROR, Constantes.MENSAJE_ARCHIVO_MULTIPART_REQUERIDO));
    }
}
