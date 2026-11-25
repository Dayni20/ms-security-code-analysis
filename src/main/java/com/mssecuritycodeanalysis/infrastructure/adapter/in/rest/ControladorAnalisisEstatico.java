package com.mssecuritycodeanalysis.infrastructure.adapter.in.rest;

import java.io.IOException;
import java.io.InputStream;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.mssecuritycodeanalysis.application.service.ServicioAnalisisEstatico;
import com.mssecuritycodeanalysis.domain.Constantes;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisEstatico;

@RestController
public class ControladorAnalisisEstatico {

    private final ServicioAnalisisEstatico servicio;

    public ControladorAnalisisEstatico(ServicioAnalisisEstatico servicio) {
        this.servicio = servicio;
    }

    @PostMapping(value = Constantes.RUTA_ANALISIS_ESTATICO, consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public RespuestaAnalisisEstatico analizar(
            @RequestParam(Constantes.CAMPO_ARCHIVO_MULTIPART) MultipartFile archivo) throws IOException {
        try (InputStream entrada = archivo.getInputStream()) {
            ResultadoAnalisisEstatico resultado = servicio.analizar(archivo.getOriginalFilename(), entrada);
            return new RespuestaAnalisisEstatico(archivo.getOriginalFilename(),
                    Constantes.ESTADO_ANALISIS_COMPLETADO, resultado);
        }
    }

    public record RespuestaAnalisisEstatico(String nombreArchivoZip, String estado,
            ResultadoAnalisisEstatico resultado) {
    }
}
