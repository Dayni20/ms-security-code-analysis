package com.mssecuritycodeanalysis.infrastructure.adapter.out.evaluacion;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mssecuritycodeanalysis.application.port.out.RepositorioEvaluaciones;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionEvaluacion;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionEvaluacion.Motivo;
import com.mssecuritycodeanalysis.domain.model.evaluacion.EvaluacionExperimental;

public class RepositorioEvaluacionesJson implements RepositorioEvaluaciones {
    private final Path directorio;
    private final ObjectMapper mapper;
    public RepositorioEvaluacionesJson(Path directorio, ObjectMapper mapper) {
        this.directorio = directorio.toAbsolutePath().normalize();
        this.mapper = mapper;
    }
    @Override
    public synchronized void crear(EvaluacionExperimental evaluacion) {
        try {
            Files.createDirectories(directorio);
            Files.createDirectory(directorio.resolve(evaluacion.identificador().toString()));
            guardar(evaluacion);
        } catch (IOException excepcion) { throw fallo(excepcion); }
    }
    @Override
    public synchronized void guardar(EvaluacionExperimental evaluacion) {
        Path carpeta = directorio.resolve(evaluacion.identificador().toString());
        Path temporal = null;
        try {
            temporal = Files.createTempFile(carpeta, "resultado-", ".tmp");
            mapper.writerWithDefaultPrettyPrinter().writeValue(temporal.toFile(), new Registro(evaluacion, evaluacion.resumen()));
            try {
                Files.move(temporal, carpeta.resolve("evaluacion.json"), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException excepcion) {
                Files.move(temporal, carpeta.resolve("evaluacion.json"), StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException excepcion) { throw fallo(excepcion); }
        finally {
            if (temporal != null) {
                try { Files.deleteIfExists(temporal); }
                catch (IOException excepcion) { throw fallo(excepcion); }
            }
        }
    }
    @Override
    public synchronized Optional<EvaluacionExperimental> buscar(UUID identificador) {
        Path archivo = directorio.resolve(identificador.toString()).resolve("evaluacion.json");
        if (!Files.exists(archivo)) return Optional.empty();
        try {
            EvaluacionExperimental evaluacion = mapper.readValue(archivo.toFile(), Registro.class).evaluacion();
            if (!identificador.equals(evaluacion.identificador())) throw new IOException("Identificador persistido inconsistente");
            return Optional.of(evaluacion);
        } catch (IOException excepcion) { throw fallo(excepcion); }
    }
    @Override
    public synchronized List<EvaluacionExperimental> listar() {
        if (!Files.exists(directorio)) return List.of();
        try (java.util.stream.Stream<Path> carpetas = Files.list(directorio)) {
            List<EvaluacionExperimental> resultados = new ArrayList<>();
            for (Path carpeta : carpetas.filter(Files::isDirectory).toList()) {
                UUID id;
                try { id = UUID.fromString(carpeta.getFileName().toString()); }
                catch (IllegalArgumentException excepcion) { continue; }
                buscar(id).ifPresent(resultados::add);
            }
            return List.copyOf(resultados);
        } catch (IOException excepcion) { throw fallo(excepcion); }
    }
    public record Registro(EvaluacionExperimental evaluacion, EvaluacionExperimental.Resumen resumen) { }

    private ExcepcionEvaluacion fallo(IOException causa) {
        return new ExcepcionEvaluacion(Motivo.ALMACENAMIENTO, "No se pudieron leer o guardar los resultados experimentales", causa);
    }
}
