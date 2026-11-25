package com.mssecuritycodeanalysis.infrastructure.adapter.in.rest;

import java.io.IOException;
import java.io.InputStream;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.mssecuritycodeanalysis.application.service.ServicioAnalisisIA;
import com.mssecuritycodeanalysis.domain.Constantes;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisIA;

@RestController
public class ControladorAnalisisIA {

    private final ServicioAnalisisIA servicio;

    public ControladorAnalisisIA(ServicioAnalisisIA servicio) {
        this.servicio = servicio;
    }

    @PostMapping(value = Constantes.RUTA_ANALISIS_IA, consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public RespuestaAnalisisIA analizar(@RequestParam(Constantes.CAMPO_ARCHIVO_MULTIPART) MultipartFile archivo)
            throws IOException {
        try (InputStream entrada = archivo.getInputStream()) {
            ResultadoAnalisisIA resultado = servicio.analizar(archivo.getOriginalFilename(), entrada);
            return new RespuestaAnalisisIA(archivo.getOriginalFilename(), resultado.estado(), resultado);
        }
    }

    public record RespuestaAnalisisIA(String nombreArchivoZip, String estado, ResultadoAnalisisIA resultado) {
    }
}
