package com.mssecuritycodeanalysis.infrastructure.adapter.out.semgrep;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisEstatico;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisEstatico.Motivo;
import com.mssecuritycodeanalysis.domain.Constantes;
import com.mssecuritycodeanalysis.infrastructure.config.PropiedadesSemgrep;
import com.mssecuritycodeanalysis.infrastructure.config.PropiedadesSemgrep.ModoEjecucion;

public class EjecutorSemgrep {

    private final PropiedadesSemgrep propiedades;
    private final long maxBytesArchivo;

    public EjecutorSemgrep(PropiedadesSemgrep propiedades, long maxBytesArchivo) {
        this.propiedades = propiedades;
        this.maxBytesArchivo = maxBytesArchivo;
    }

    public SalidaSemgrep ejecutar(Path directorioTrabajo, Path directorioFuentes, Path reglas) {
        String directorioAnalizador = usaWsl()
                ? convertirDirectorioWsl(directorioTrabajo) : directorioTrabajo.toString();
        Process proceso = iniciarProceso(directorioTrabajo, directorioFuentes, reglas, directorioAnalizador);
        ExecutorService lectores = Executors.newVirtualThreadPerTaskExecutor();
        Future<byte[]> salida = lectores.submit(() -> leerSalida(proceso.getInputStream(), proceso, directorioTrabajo));
        Future<byte[]> errores = lectores.submit(() -> leerSalida(proceso.getErrorStream(), proceso, directorioTrabajo));
        long inicio = System.nanoTime();
        try {
            proceso.getOutputStream().close();
            if (!proceso.waitFor(tiempoEsperaProceso(), TimeUnit.SECONDS)) {
                throw tiempoAgotado();
            }
            byte[] contenido = esperarLectura(salida, inicio);
            esperarLectura(errores, inicio);
            validarCodigoSalida(proceso.exitValue());
            return new SalidaSemgrep(contenido, directorioAnalizador);
        } catch (InterruptedException excepcion) {
            Thread.currentThread().interrupt();
            throw ejecucionFallida(excepcion);
        } catch (IOException excepcion) {
            throw ejecucionFallida(excepcion);
        } finally {
            finalizarProceso(proceso, directorioTrabajo);
            salida.cancel(true);
            errores.cancel(true);
            lectores.shutdownNow();
        }
    }

    private Process iniciarProceso(Path trabajo, Path fuentes, Path reglas, String directorioAnalizador) {
        try {
            if (usaWsl()) {
                prepararLanzadorWsl(trabajo);
            }
            ProcessBuilder constructor = new ProcessBuilder(crearComando(trabajo, fuentes, reglas, directorioAnalizador));
            constructor.directory(trabajo.toFile());
            configurarEntorno(constructor.environment(), trabajo);
            return constructor.start();
        } catch (IOException excepcion) {
            throw new ExcepcionAnalisisEstatico(Constantes.MENSAJE_SEMGREP_NO_DISPONIBLE,
                    Motivo.NO_DISPONIBLE, excepcion);
        }
    }

    private void configurarEntorno(Map<String, String> entorno, Path trabajo) {
        entorno.remove(Constantes.VARIABLE_PYTHONPATH);
        entorno.remove(Constantes.VARIABLE_PYTHONSTARTUP);
        entorno.remove(Constantes.VARIABLE_TOKEN_SEMGREP);
        entorno.put(Constantes.VARIABLE_PYTHONUTF8, Constantes.VALOR_ACTIVADO);
        if (!usaWsl()) {
            entorno.put(Constantes.VARIABLE_CONFIGURACION_SEMGREP,
                    trabajo.resolve(Constantes.ARCHIVO_CONFIGURACION_SEMGREP).toString());
        }
    }

    private List<String> crearComando(Path trabajo, Path fuentes, Path reglas, String directorioAnalizador) {
        List<String> comando = new ArrayList<>();
        if (usaWsl()) {
            comando.addAll(List.of(propiedades.wslEjecutable(), Constantes.OPCION_DISTRIBUCION_WSL,
                    propiedades.wslDistribucion(), Constantes.OPCION_DIRECTORIO_WSL, directorioAnalizador,
                    Constantes.OPCION_EJECUTAR_WSL, Constantes.COMANDO_PYTHON_WSL,
                    Constantes.OPCION_PYTHON_AISLADO, Constantes.ARCHIVO_LANZADOR_WSL,
                    Long.toString(propiedades.tiempoMaximoSegundos()), Constantes.ARCHIVO_CANCELACION_WSL,
                    propiedades.wslEjecutableSemgrep()));
        } else {
            Path ejecutable = Path.of(propiedades.ejecutable());
            comando.add(ejecutable.getParent() == null
                    ? propiedades.ejecutable() : ejecutable.toAbsolutePath().normalize().toString());
        }
        comando.addAll(crearArgumentosSemgrep(trabajo, fuentes, reglas));
        return comando;
    }

    private List<String> crearArgumentosSemgrep(Path trabajo, Path fuentes, Path reglas) {
        String rutaReglas = obtenerRutaRelativa(trabajo, reglas);
        String rutaFuentes = obtenerRutaRelativa(trabajo, fuentes);
        return List.of(Constantes.COMANDO_ESCANEAR, Constantes.OPCION_CONFIGURACION, rutaReglas,
                Constantes.OPCION_JSON, Constantes.OPCION_MOTOR_COMUNITARIO, Constantes.OPCION_ESTRICTA,
                Constantes.OPCION_SIN_ERROR_POR_HALLAZGOS, Constantes.OPCION_SIN_REESCRITURA_REGLAS,
                Constantes.OPCION_METRICAS_DESACTIVADAS, Constantes.OPCION_SIN_REVISION_VERSION,
                Constantes.OPCION_SIN_GITIGNORE, Constantes.OPCION_SIN_NOSEM,
                Constantes.OPCION_SIN_AUTOCORRECCION, Constantes.OPCION_UN_TRABAJADOR,
                Constantes.OPCION_MAX_BYTES_ARCHIVO, Long.toString(maxBytesArchivo),
                Constantes.OPCION_TIEMPO_REGLA, Long.toString(propiedades.tiempoMaximoSegundos()),
                Constantes.OPCION_FIN_ARGUMENTOS, rutaFuentes);
    }

    private String obtenerRutaRelativa(Path trabajo, Path destino) {
        return trabajo.relativize(destino).toString()
                .replace(Constantes.CARACTER_SEPARADOR_WINDOWS, Constantes.CARACTER_SEPARADOR_UNIX);
    }

    private String convertirDirectorioWsl(Path trabajo) {
        Process proceso = null;
        try {
            ProcessBuilder constructor = new ProcessBuilder(propiedades.wslEjecutable(),
                    Constantes.OPCION_DISTRIBUCION_WSL, propiedades.wslDistribucion(),
                    Constantes.OPCION_EJECUTAR_WSL, Constantes.COMANDO_WSLPATH,
                    Constantes.OPCION_RUTA_ABSOLUTA_WSL, Constantes.OPCION_RUTA_LINUX_WSL, trabajo.toString());
            constructor.redirectError(ProcessBuilder.Redirect.DISCARD);
            proceso = constructor.start();
            proceso.getOutputStream().close();
            if (!proceso.waitFor(propiedades.tiempoMaximoSegundos(), TimeUnit.SECONDS)) {
                throw tiempoAgotado();
            }
            byte[] salida = proceso.getInputStream().readNBytes(4097);
            String ruta = new String(salida, StandardCharsets.UTF_8).strip();
            if (proceso.exitValue() != 0 || salida.length > 4096
                    || !ruta.startsWith(Constantes.SEPARADOR_RUTA_UNIX)
                    || ruta.chars().anyMatch(Character::isISOControl)) {
                throw new ExcepcionAnalisisEstatico(Constantes.MENSAJE_RUTA_WSL_INVALIDA,
                        Motivo.CONFIGURACION_INVALIDA);
            }
            return ruta;
        } catch (IOException excepcion) {
            throw new ExcepcionAnalisisEstatico(Constantes.MENSAJE_SEMGREP_NO_DISPONIBLE,
                    Motivo.NO_DISPONIBLE, excepcion);
        } catch (InterruptedException excepcion) {
            Thread.currentThread().interrupt();
            throw ejecucionFallida(excepcion);
        } finally {
            if (proceso != null && proceso.isAlive()) {
                detenerProcesoNativo(proceso);
            }
        }
    }

    private void prepararLanzadorWsl(Path trabajo) throws IOException {
        try (InputStream recurso = EjecutorSemgrep.class.getResourceAsStream(Constantes.RECURSO_LANZADOR_WSL)) {
            if (recurso == null) {
                throw new ExcepcionAnalisisEstatico(Constantes.MENSAJE_REGLAS_INVALIDAS,
                        Motivo.CONFIGURACION_INVALIDA);
            }
            Files.copy(recurso, trabajo.resolve(Constantes.ARCHIVO_LANZADOR_WSL));
        }
    }

    private byte[] leerSalida(InputStream entrada, Process proceso, Path trabajo) throws IOException {
        try (InputStream flujo = entrada; ByteArrayOutputStream contenido = new ByteArrayOutputStream()) {
            byte[] bloque = new byte[8192];
            int bytesLeidos;
            while ((bytesLeidos = flujo.read(bloque)) != -1) {
                if (bytesLeidos > propiedades.maxBytesSalida() - contenido.size()) {
                    solicitarDetencion(proceso, trabajo);
                    throw new ExcepcionAnalisisEstatico(Constantes.MENSAJE_SALIDA_SEMGREP_EXCESIVA,
                            Motivo.SALIDA_INVALIDA);
                }
                contenido.write(bloque, 0, bytesLeidos);
            }
            return contenido.toByteArray();
        }
    }

    private byte[] esperarLectura(Future<byte[]> lectura, long inicio) throws InterruptedException {
        long restante = TimeUnit.SECONDS.toNanos(tiempoEsperaProceso()) - (System.nanoTime() - inicio);
        if (restante <= 0) {
            throw tiempoAgotado();
        }
        try {
            return lectura.get(restante, TimeUnit.NANOSECONDS);
        } catch (TimeoutException excepcion) {
            throw tiempoAgotado();
        } catch (ExecutionException excepcion) {
            if (excepcion.getCause() instanceof ExcepcionAnalisisEstatico error) {
                throw error;
            }
            throw ejecucionFallida(excepcion.getCause());
        }
    }

    private void validarCodigoSalida(int codigo) {
        if (usaWsl() && codigo == 124) {
            throw tiempoAgotado();
        }
        if (usaWsl() && (codigo == 126 || codigo == 127)) {
            throw new ExcepcionAnalisisEstatico(Constantes.MENSAJE_SEMGREP_NO_DISPONIBLE, Motivo.NO_DISPONIBLE);
        }
        if (codigo != 0) {
            throw ejecucionFallida(null);
        }
    }

    private void solicitarDetencion(Process proceso, Path trabajo) {
        if (!proceso.isAlive()) {
            return;
        }
        if (!usaWsl()) {
            detenerProcesoNativo(proceso);
            return;
        }
        try {
            Files.writeString(trabajo.resolve(Constantes.ARCHIVO_CANCELACION_WSL), Constantes.TEXTO_VACIO,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        } catch (IOException excepcion) {
            detenerProcesoNativo(proceso);
        }
    }

    private void finalizarProceso(Process proceso, Path trabajo) {
        solicitarDetencion(proceso, trabajo);
        boolean interrumpido = Thread.interrupted();
        try {
            if (!proceso.waitFor(5, TimeUnit.SECONDS)) {
                detenerProcesoNativo(proceso);
            }
        } catch (InterruptedException excepcion) {
            interrumpido = true;
            detenerProcesoNativo(proceso);
        } finally {
            if (interrumpido) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private void detenerProcesoNativo(Process proceso) {
        List<ProcessHandle> descendientes = proceso.descendants().toList();
        for (ProcessHandle descendiente : descendientes) {
            descendiente.destroyForcibly();
        }
        if (proceso.isAlive()) {
            proceso.destroyForcibly();
        }
    }

    private boolean usaWsl() {
        return propiedades.modoEjecucion() == ModoEjecucion.WSL;
    }

    private long tiempoEsperaProceso() {
        return propiedades.tiempoMaximoSegundos() + (usaWsl() ? 10 : 0);
    }

    private ExcepcionAnalisisEstatico tiempoAgotado() {
        return new ExcepcionAnalisisEstatico(Constantes.MENSAJE_TIEMPO_SEMGREP_AGOTADO, Motivo.TIEMPO_AGOTADO);
    }

    private ExcepcionAnalisisEstatico ejecucionFallida(Throwable causa) {
        return new ExcepcionAnalisisEstatico(Constantes.MENSAJE_EJECUCION_SEMGREP_FALLIDA,
                Motivo.EJECUCION_FALLIDA, causa);
    }

    public record SalidaSemgrep(byte[] contenido, String directorioAnalizador) {
    }
}
