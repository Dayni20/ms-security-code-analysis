package com.mssecuritycodeanalysis.infrastructure.adapter.in.rest;

import java.io.IOException;
import java.util.List;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.mssecuritycodeanalysis.application.service.ServicioCargaProyectoFuente;
import com.mssecuritycodeanalysis.domain.Constantes;
import com.mssecuritycodeanalysis.domain.model.ArchivoFuente;

@RestController
public class ControladorCargaProyecto {

    private final ServicioCargaProyectoFuente servicio;

    public ControladorCargaProyecto(ServicioCargaProyectoFuente servicio) {
        this.servicio = servicio;
    }

    @PostMapping(value = Constantes.RUTA_CARGA_PROYECTO, consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public RespuestaCarga cargar(@RequestParam(Constantes.CAMPO_ARCHIVO_MULTIPART) MultipartFile archivo) throws IOException {
        try (var entrada = archivo.getInputStream()) {
            List<ArchivoFuente> archivos = servicio.cargar(archivo.getOriginalFilename(), entrada);
            return crearRespuesta(archivo.getOriginalFilename(), archivos);
        }
    }

    private RespuestaCarga crearRespuesta(String nombreArchivo, List<ArchivoFuente> archivos) {
        List<ArchivoIdentificado> archivosIdentificados = archivos.stream()
                .map(archivo -> new ArchivoIdentificado(archivo.rutaRelativa(), archivo.lenguaje()))
                .toList();
        return new RespuestaCarga(nombreArchivo, archivos.size(), archivosIdentificados);
    }

    public record RespuestaCarga(String nombreArchivoZip, int cantidadArchivosFuente,
            List<ArchivoIdentificado> archivos) {
    }

    public record ArchivoIdentificado(String rutaRelativa, String lenguaje) {
    }
}
