package com.mssecuritycodeanalysis.application.service;

import java.io.InputStream;
import java.util.List;
import java.util.HashSet;
import java.util.function.Supplier;
import com.mssecuritycodeanalysis.application.port.out.*;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisIA;
import com.mssecuritycodeanalysis.domain.Constantes;
import com.mssecuritycodeanalysis.domain.model.*;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisHibrido.*;
import com.mssecuritycodeanalysis.domain.service.CorrelacionadorHallazgos;

public class ServicioAnalisisHibrido {
    private final ServicioCargaProyectoFuente carga;
    private final AnalizadorEstatico estatico;
    private final AnalizadorIA ia;
    public ServicioAnalisisHibrido(ServicioCargaProyectoFuente carga, AnalizadorEstatico estatico, AnalizadorIA ia) {
        this.carga = carga;
        this.estatico = estatico;
        this.ia = ia;
    }
    public synchronized ResultadoAnalisisHibrido analizar(String nombre, InputStream entrada) {
        long inicio = System.nanoTime();
        List<ArchivoFuente> archivos = carga.cargar(nombre, entrada);
        long tiempoCarga = tiempo(inicio);
        ResultadoMetodo<ResultadoAnalisisEstatico> resultadoEstatico = ejecutar(() -> estatico.analizar(archivos), archivos);
        ResultadoMetodo<ResultadoAnalisisIA> resultadoIA = ejecutar(() -> ia.analizar(archivos), archivos);
        long correlacion = System.nanoTime();
        HashSet<String> comunes = new HashSet<>(resultadoEstatico.cobertura().archivosAnalizados());
        comunes.retainAll(resultadoIA.cobertura().archivosAnalizados());
        List<HallazgoSeguridad> alertasEstaticas = resultadoEstatico.resultado() == null ? List.of() : resultadoEstatico.resultado().hallazgos();
        List<HallazgoSeguridad> alertasIA = resultadoIA.resultado() == null ? List.of() : resultadoIA.resultado().hallazgos();
        List<HallazgoHibrido> hallazgos = new CorrelacionadorHallazgos().correlacionar(archivos, alertasEstaticas, alertasIA, comunes);
        String estado = Constantes.ESTADO_ANALISIS_COMPLETADO.equals(resultadoEstatico.estado()) && Constantes.ESTADO_ANALISIS_COMPLETADO.equals(resultadoIA.estado())
                ? Constantes.ESTADO_ANALISIS_COMPLETADO : resultadoEstatico.resultado() == null && resultadoIA.resultado() == null
                ? Constantes.ESTADO_ANALISIS_ERROR : Constantes.ESTADO_ANALISIS_PARCIAL;
        HashSet<String> analizados = new HashSet<>(resultadoEstatico.cobertura().archivosAnalizados());
        analizados.addAll(resultadoIA.cobertura().archivosAnalizados());
        return new ResultadoAnalisisHibrido(estado, resultadoEstatico, resultadoIA, hallazgos,
                archivos.stream().map(ArchivoFuente::rutaRelativa).toList(), analizados.stream().sorted().toList(),
                new TiemposEjecucion(tiempoCarga, resultadoEstatico.tiempoMilisegundos(), resultadoIA.tiempoMilisegundos(), tiempo(correlacion), tiempo(inicio), false),
                Constantes.VERSION_CORRELACION, List.of(Constantes.CORRELACION_OPERACION, Constantes.CORRELACION_PROPAGACION),
                List.of(Constantes.LIMITACION_EVIDENCIA, Constantes.LIMITACION_CORRELACION, Constantes.LIMITACION_PARCIALES));
    }
    private <T> ResultadoMetodo<T> ejecutar(Supplier<T> tarea, List<ArchivoFuente> archivos) {
        long inicio = System.nanoTime();
        T resultado = null;
        String error = null;
        String motivo = null;
        try { resultado = tarea.get(); }
        catch (RuntimeException excepcion) {
            error = Constantes.MENSAJE_ERROR_HIBRIDO;
            motivo = Constantes.MOTIVO_ERROR_INTERNO;
            if (excepcion instanceof ExcepcionAnalisisIA fallo) {
                @SuppressWarnings("unchecked") T parcial = (T) fallo.resultadoParcial();
                resultado = parcial;
                motivo = fallo.motivo().name();
                error = fallo.getMessage();
            } else if (excepcion instanceof com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisEstatico fallo) {
                motivo = fallo.motivo().name();
                error = fallo.getMessage();
            }
        }
        List<String> cubiertos = List.of(), sinCobertura = List.of(), analizados = List.of();
        boolean completo = error == null;
        if (resultado instanceof ResultadoAnalisisEstatico datos) {
            cubiertos = datos.lenguajesConReglas(); sinCobertura = datos.lenguajesSinReglas(); analizados = datos.archivosAnalizados();
        } else if (resultado instanceof ResultadoAnalisisIA datos) {
            cubiertos = datos.lenguajesConCobertura(); sinCobertura = datos.lenguajesSinCobertura(); analizados = datos.archivosAnalizados();
            completo &= Constantes.ESTADO_ANALISIS_COMPLETADO.equals(datos.estado());
        }
        List<String> reconocidos = archivos.stream().map(ArchivoFuente::lenguaje).distinct().sorted().toList();
        HashSet<String> conocidos = new HashSet<>(cubiertos); conocidos.addAll(sinCobertura);
        HashSet<String> procesados = new HashSet<>(analizados);
        List<String> pendientes = archivos.stream().map(ArchivoFuente::rutaRelativa).filter(ruta -> !procesados.contains(ruta)).toList();
        completo &= pendientes.isEmpty() && sinCobertura.isEmpty();
        String estado = resultado == null ? Constantes.ESTADO_ANALISIS_ERROR : completo ? Constantes.ESTADO_ANALISIS_COMPLETADO : Constantes.ESTADO_ANALISIS_PARCIAL;
        return new ResultadoMetodo<>(estado, resultado, motivo, error, tiempo(inicio), new CoberturaAnalizador(reconocidos, cubiertos, sinCobertura,
                reconocidos.stream().filter(lenguaje -> !conocidos.contains(lenguaje)).toList(), analizados, pendientes));
    }
    private long tiempo(long inicio) { return (System.nanoTime() - inicio) / 1_000_000; }
}
