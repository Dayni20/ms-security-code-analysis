package com.mssecuritycodeanalysis.infrastructure.adapter.in.rest;

import java.net.URI;
import java.util.List;
import java.util.ArrayList;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.annotation.JsonCreator;
import java.util.UUID;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import com.mssecuritycodeanalysis.application.service.ServicioEvaluacionExperimental;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionEvaluacion;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionEvaluacion.Motivo;
import com.mssecuritycodeanalysis.domain.model.evaluacion.*;

@RestController
@RequestMapping("/api/v1/evaluation")
public class ControladorEvaluacionExperimental {
    private final ServicioEvaluacionExperimental servicio;
    private final ExportadorEvaluacionCsv exportador = new ExportadorEvaluacionCsv();
    public ControladorEvaluacionExperimental(ServicioEvaluacionExperimental servicio) { this.servicio = servicio; }
    @PostMapping("/run")
    public ResponseEntity<EvaluacionExperimental.Resumen> iniciar(@RequestBody(required = false) SolicitudEvaluacion solicitud) {
        EvaluacionExperimental.Resumen resumen = servicio.iniciar(solicitud == null ? null : solicitud.identificadores());
        return ResponseEntity.accepted().location(URI.create("/api/v1/evaluation/" + resumen.identificador())).body(resumen);
    }
    @GetMapping("/{id}")
    public EvaluacionExperimental.Resumen consultar(@PathVariable UUID id) { return servicio.consultar(id).resumen(); }
    @GetMapping("/{id}/results")
    public DetalleResultados resultados(@PathVariable UUID id) {
        EvaluacionExperimental evaluacion = servicio.consultar(id);
        return new DetalleResultados(evaluacion.resumen(), evaluacion.resultados());
    }
    @GetMapping("/{id}/export")
    public ResponseEntity<byte[]> exportar(@PathVariable UUID id) {
        EvaluacionExperimental evaluacion = servicio.consultar(id);
        if (!evaluacion.estado().finalizado()) throw new ExcepcionEvaluacion(Motivo.NO_FINALIZADA, "La evaluacion aun no ha finalizado");
        return ResponseEntity.ok().contentType(MediaType.parseMediaType("text/csv;charset=UTF-8"))
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment().filename("evaluacion-" + id + ".csv").build().toString())
                .body(exportador.exportar(evaluacion));
    }
    public record SolicitudEvaluacion(List<String> identificadores) {
        @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
        public static SolicitudEvaluacion leer(JsonNode solicitud) {
            if (!solicitud.isObject()) throw new IllegalArgumentException("Se requiere un objeto JSON");
            solicitud.fieldNames().forEachRemaining(nombre -> {
                if (!"identificadores".equals(nombre)) throw new IllegalArgumentException("Campo no admitido: " + nombre);
            });
            JsonNode seleccion = solicitud.path("identificadores");
            if (seleccion.isMissingNode() || seleccion.isNull()) return new SolicitudEvaluacion(null);
            if (!seleccion.isArray()) throw new IllegalArgumentException("Se requiere una lista de identificadores");
            List<String> identificadores = new ArrayList<>();
            for (JsonNode valor : seleccion) {
                if (!valor.isTextual() || valor.asText().isBlank()) throw new IllegalArgumentException("Identificador no valido");
                identificadores.add(valor.asText());
            }
            return new SolicitudEvaluacion(List.copyOf(identificadores));
        }
    }
    public record DetalleResultados(EvaluacionExperimental.Resumen resumen, List<ResultadoCasoExperimental> resultados) { }
}
