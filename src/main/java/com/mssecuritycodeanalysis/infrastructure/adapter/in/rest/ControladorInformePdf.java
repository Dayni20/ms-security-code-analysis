package com.mssecuritycodeanalysis.infrastructure.adapter.in.rest;

import java.io.IOException;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import com.mssecuritycodeanalysis.application.service.ServicioInformePdf;
import com.mssecuritycodeanalysis.domain.Constantes;
import com.mssecuritycodeanalysis.domain.model.InformeAnalisis;

@RestController
public class ControladorInformePdf {
    private final ServicioInformePdf servicio;
    private final LectorSolicitudInforme lector;

    public ControladorInformePdf(ServicioInformePdf servicio, LectorSolicitudInforme lector) {
        this.servicio = servicio;
        this.lector = lector;
    }

    @PostMapping(value = Constantes.RUTA_INFORME_PDF, consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<byte[]> generar(HttpServletRequest solicitud) throws IOException {
        InformeAnalisis informe = lector.leer(solicitud.getInputStream());
        byte[] pdf = servicio.generar(informe);
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_PDF)
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment().filename(Constantes.NOMBRE_DESCARGA_PDF).build().toString())
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header("X-Content-Type-Options", "nosniff")
                .contentLength(pdf.length).body(pdf);
    }

    @ExceptionHandler({IllegalArgumentException.class, IOException.class})
    public ResponseEntity<Map<String, String>> solicitudInvalida(Exception excepcion) {
        return ResponseEntity.badRequest().body(Map.of(Constantes.CLAVE_ERROR, Constantes.MENSAJE_SOLICITUD_PDF_INVALIDA));
    }

    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<Map<String, String>> generacionFallida(IllegalStateException excepcion) {
        return ResponseEntity.internalServerError().body(Map.of(Constantes.CLAVE_ERROR, Constantes.MENSAJE_ERROR_PDF));
    }
}
