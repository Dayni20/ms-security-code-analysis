package com.mssecuritycodeanalysis.infrastructure.adapter.out.semgrep;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import com.mssecuritycodeanalysis.application.port.out.AnalizadorEstatico;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisEstatico;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisEstatico.Motivo;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionProyectoInvalido;
import com.mssecuritycodeanalysis.domain.Constantes;
import com.mssecuritycodeanalysis.domain.model.ArchivoFuente;
import com.mssecuritycodeanalysis.domain.model.HallazgoSeguridad;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisEstatico;
import com.mssecuritycodeanalysis.infrastructure.adapter.out.semgrep.InterpreteResultadoSemgrep.LecturaSemgrep;
import com.mssecuritycodeanalysis.infrastructure.adapter.out.semgrep.EjecutorSemgrep.SalidaSemgrep;
import com.mssecuritycodeanalysis.infrastructure.config.PropiedadesSemgrep;

public class AnalizadorSemgrep implements AnalizadorEstatico {

    private final PropiedadesSemgrep propiedades;
    private final Path directorioTemporal;
    private final EjecutorSemgrep ejecutor;
    private final InterpreteResultadoSemgrep interprete;

    public AnalizadorSemgrep(PropiedadesSemgrep propiedades, Path directorioTemporal,
            EjecutorSemgrep ejecutor, InterpreteResultadoSemgrep interprete) {
        this.propiedades = propiedades;
        this.directorioTemporal = directorioTemporal;
        this.ejecutor = ejecutor;
        this.interprete = interprete;
    }

    @Override
    public ResultadoAnalisisEstatico analizar(List<ArchivoFuente> archivos) {
        ReglasLocales reglas = cargarReglas();
        List<ArchivoFuente> archivosConReglas = archivos.stream()
                .filter(archivo -> reglas.lenguajes().contains(archivo.lenguaje())).toList();
        if (archivosConReglas.isEmpty()) {
            throw new ExcepcionAnalisisEstatico(Constantes.MENSAJE_SIN_COBERTURA, Motivo.SIN_COBERTURA);
        }
        Path trabajo = crearDirectorioTrabajo();
        RuntimeException fallo = null;
        try {
            return analizarEnDirectorio(archivos, archivosConReglas, reglas, trabajo);
        } catch (IOException excepcion) {
            fallo = new ExcepcionAnalisisEstatico(Constantes.MENSAJE_PREPARACION_ANALISIS_FALLIDA,
                    Motivo.EJECUCION_FALLIDA, excepcion);
            throw fallo;
        } catch (RuntimeException excepcion) {
            fallo = excepcion;
            throw excepcion;
        } finally {
            eliminarDirectorioTrabajo(trabajo, fallo);
        }
    }

    private ResultadoAnalisisEstatico analizarEnDirectorio(List<ArchivoFuente> archivos,
            List<ArchivoFuente> archivosConReglas, ReglasLocales reglas, Path trabajo) throws IOException {
        Path fuentes = Files.createDirectory(trabajo.resolve(Constantes.DIRECTORIO_FUENTES));
        Set<String> rutasPermitidas = prepararArchivos(archivos, fuentes);
        crearArchivoIgnore(trabajo);
        crearArchivoIgnore(fuentes);
        Path archivoReglas = trabajo.resolve(Constantes.ARCHIVO_REGLAS_TEMPORALES);
        Files.write(archivoReglas, reglas.contenido(), StandardOpenOption.CREATE_NEW);
        SalidaSemgrep salida = ejecutor.ejecutar(trabajo, fuentes, archivoReglas);
        LecturaSemgrep lectura = interprete.interpretar(salida, trabajo, fuentes, rutasPermitidas,
                reglas.identificadores());
        List<String> archivosAnalizados = validarCoberturaArchivos(archivosConReglas, lectura);
        List<String> reconocidos = obtenerLenguajes(archivos);
        List<String> cubiertos = obtenerLenguajes(archivosConReglas);
        List<String> sinReglas = reconocidos.stream().filter(lenguaje -> !cubiertos.contains(lenguaje)).toList();
        return new ResultadoAnalisisEstatico(lectura.hallazgos(), reconocidos, cubiertos, sinReglas,
                archivosAnalizados, lectura.versionSemgrep(), reglas.huella());
    }

    private Path crearDirectorioTrabajo() {
        try {
            Files.createDirectories(directorioTemporal);
            return Files.createTempDirectory(directorioTemporal, Constantes.PREFIJO_TEMPORAL_ANALISIS)
                    .toAbsolutePath().normalize();
        } catch (IOException excepcion) {
            throw new ExcepcionAnalisisEstatico(Constantes.MENSAJE_PREPARACION_ANALISIS_FALLIDA,
                    Motivo.EJECUCION_FALLIDA, excepcion);
        }
    }

    private Set<String> prepararArchivos(List<ArchivoFuente> archivos, Path fuentes) throws IOException {
        Set<String> rutas = new HashSet<>();
        for (ArchivoFuente archivo : archivos) {
            Path destino = resolverRutaSegura(fuentes, archivo.rutaRelativa());
            String relativa = normalizarSeparadores(fuentes.relativize(destino).toString());
            if (!rutas.add(relativa)) {
                throw new ExcepcionProyectoInvalido(Constantes.MENSAJE_RUTAS_DUPLICADAS);
            }
            Files.createDirectories(destino.getParent());
            Files.writeString(destino, archivo.contenido(), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        }
        return Set.copyOf(rutas);
    }

    private Path resolverRutaSegura(Path fuentes, String rutaOriginal) {
        String ruta = normalizarSeparadores(rutaOriginal);
        if (ruta.isBlank() || ruta.startsWith(Constantes.SEPARADOR_RUTA_UNIX)
                || ruta.contains(Constantes.SEPARADOR_UNIDAD) || ruta.chars().anyMatch(Character::isISOControl)) {
            throw new ExcepcionProyectoInvalido(Constantes.MENSAJE_RUTA_NO_PERMITIDA);
        }
        for (String segmento : ruta.split(Constantes.SEPARADOR_RUTA_UNIX)) {
            if (segmento.isEmpty() || segmento.equals(Constantes.SEGMENTO_DIRECTORIO_PADRE)
                    || segmento.equals(Constantes.SEGMENTO_DIRECTORIO_ACTUAL)) {
                throw new ExcepcionProyectoInvalido(Constantes.MENSAJE_RUTA_NO_PERMITIDA);
            }
        }
        try {
            Path destino = fuentes.resolve(ruta).normalize();
            if (!destino.startsWith(fuentes) || destino.equals(fuentes)) {
                throw new ExcepcionProyectoInvalido(Constantes.MENSAJE_RUTA_NO_PERMITIDA);
            }
            return destino;
        } catch (InvalidPathException excepcion) {
            throw new ExcepcionProyectoInvalido(Constantes.MENSAJE_RUTA_NO_PERMITIDA);
        }
    }

    private void crearArchivoIgnore(Path directorio) throws IOException {
        Files.writeString(directorio.resolve(Constantes.ARCHIVO_SEMGREPIGNORE), Constantes.TEXTO_VACIO,
                StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
    }

    private List<String> validarCoberturaArchivos(List<ArchivoFuente> archivosConReglas, LecturaSemgrep lectura) {
        Set<String> esperados = archivosConReglas.stream().map(archivo -> normalizarSeparadores(archivo.rutaRelativa()))
                .collect(Collectors.toSet());
        if (!lectura.archivosAnalizados().containsAll(esperados)) {
            throw new ExcepcionAnalisisEstatico(Constantes.MENSAJE_SALIDA_SEMGREP_INVALIDA, Motivo.SALIDA_INVALIDA);
        }
        for (HallazgoSeguridad hallazgo : lectura.hallazgos()) {
            if (!esperados.contains(hallazgo.rutaRelativa())
                    || !lectura.archivosAnalizados().contains(hallazgo.rutaRelativa())) {
                throw new ExcepcionAnalisisEstatico(Constantes.MENSAJE_SALIDA_SEMGREP_INVALIDA, Motivo.SALIDA_INVALIDA);
            }
        }
        return esperados.stream().sorted().toList();
    }

    private List<String> obtenerLenguajes(List<ArchivoFuente> archivos) {
        return archivos.stream().map(ArchivoFuente::lenguaje).distinct().sorted().toList();
    }

    private String normalizarSeparadores(String ruta) {
        return ruta.replace(Constantes.CARACTER_SEPARADOR_WINDOWS, Constantes.CARACTER_SEPARADOR_UNIX);
    }

    private ReglasLocales cargarReglas() {
        try {
            byte[] contenido = Files.readAllBytes(propiedades.reglas().toAbsolutePath().normalize());
            LoaderOptions opciones = new LoaderOptions();
            opciones.setAllowDuplicateKeys(false);
            Yaml lector = new Yaml(new SafeConstructor(opciones));
            Object documento = lector.load(new String(contenido, StandardCharsets.UTF_8));
            if (!(documento instanceof Map<?, ?> mapa)
                    || !(mapa.get(Constantes.CAMPO_REGLAS) instanceof List<?> reglas) || reglas.isEmpty()) {
                throw configuracionInvalida();
            }
            Set<String> identificadores = new HashSet<>();
            Set<String> lenguajes = new HashSet<>();
            for (Object regla : reglas) {
                leerRegla(regla, identificadores, lenguajes);
            }
            byte[] huella = MessageDigest.getInstance(Constantes.ALGORITMO_HUELLA_REGLAS).digest(contenido);
            return new ReglasLocales(contenido, Set.copyOf(identificadores), Set.copyOf(lenguajes),
                    HexFormat.of().formatHex(huella));
        } catch (IOException | NoSuchAlgorithmException excepcion) {
            throw new ExcepcionAnalisisEstatico(Constantes.MENSAJE_REGLAS_INVALIDAS,
                    Motivo.CONFIGURACION_INVALIDA, excepcion);
        } catch (RuntimeException excepcion) {
            if (excepcion instanceof ExcepcionAnalisisEstatico error) {
                throw error;
            }
            throw new ExcepcionAnalisisEstatico(Constantes.MENSAJE_REGLAS_INVALIDAS,
                    Motivo.CONFIGURACION_INVALIDA, excepcion);
        }
    }

    private void leerRegla(Object valor, Set<String> identificadores, Set<String> lenguajes) {
        if (!(valor instanceof Map<?, ?> regla)
                || !(regla.get(Constantes.CAMPO_IDENTIFICADOR_REGLA) instanceof String identificador)
                || identificador.isBlank() || !identificadores.add(identificador)) {
            throw configuracionInvalida();
        }
        if (!(regla.get(Constantes.CAMPO_LENGUAJES_REGLA) instanceof List<?> codigos) || codigos.isEmpty()) {
            throw configuracionInvalida();
        }
        for (Object codigo : codigos) {
            String lenguaje = Constantes.LENGUAJES_SEMGREP.get(codigo);
            if (lenguaje == null) {
                throw configuracionInvalida();
            }
            lenguajes.add(lenguaje);
        }
    }

    private ExcepcionAnalisisEstatico configuracionInvalida() {
        return new ExcepcionAnalisisEstatico(Constantes.MENSAJE_REGLAS_INVALIDAS, Motivo.CONFIGURACION_INVALIDA);
    }

    private void eliminarDirectorioTrabajo(Path trabajo, RuntimeException fallo) {
        try {
            Files.walkFileTree(trabajo, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path archivo, BasicFileAttributes atributos) throws IOException {
                    Files.delete(archivo);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path directorio, IOException error) throws IOException {
                    if (error != null) {
                        throw error;
                    }
                    Files.delete(directorio);
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException excepcion) {
            if (fallo != null) {
                fallo.addSuppressed(excepcion);
            } else {
                throw new ExcepcionAnalisisEstatico(Constantes.MENSAJE_LIMPIEZA_ANALISIS_FALLIDA,
                        Motivo.LIMPIEZA_FALLIDA, excepcion);
            }
        }
    }

    private record ReglasLocales(byte[] contenido, Set<String> identificadores, Set<String> lenguajes, String huella) {
    }
}
