package com.mssecuritycodeanalysis.infrastructure.adapter.in.rest;
import java.io.IOException;
import java.io.InputStream;
import org.springframework.http.ResponseEntity;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import com.mssecuritycodeanalysis.application.service.ServicioAnalisisHibrido;
import com.mssecuritycodeanalysis.domain.Constantes;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisHibrido;
@RestController
public class ControladorAnalisisHibrido {
    private final ServicioAnalisisHibrido servicio;
    public ControladorAnalisisHibrido(ServicioAnalisisHibrido servicio) { this.servicio = servicio; }
    @PostMapping(value = Constantes.RUTA_ANALISIS_HIBRIDO, consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<RespuestaHibrida> analizar(@RequestParam(Constantes.CAMPO_ARCHIVO_MULTIPART) MultipartFile archivo) throws IOException {
        try (InputStream entrada = archivo.getInputStream()) {
            ResultadoAnalisisHibrido resultado = servicio.analizar(archivo.getOriginalFilename(), entrada);
            return ResponseEntity.status(Constantes.ESTADO_ANALISIS_ERROR.equals(resultado.estado()) ? 502 : 200)
                    .body(new RespuestaHibrida(archivo.getOriginalFilename(), resultado.estado(), resultado));
        }
    }
    public record RespuestaHibrida(String nombreArchivoZip, String estado, ResultadoAnalisisHibrido resultado) { }
}
