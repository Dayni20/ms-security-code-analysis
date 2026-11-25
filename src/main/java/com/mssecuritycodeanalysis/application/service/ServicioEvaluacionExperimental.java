package com.mssecuritycodeanalysis.application.service;

import java.io.InputStream;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import com.mssecuritycodeanalysis.application.port.out.*;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionEvaluacion;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionEvaluacion.Motivo;
import com.mssecuritycodeanalysis.domain.model.evaluacion.*;
import com.mssecuritycodeanalysis.domain.model.evaluacion.EvaluacionExperimental.Estado;
import com.mssecuritycodeanalysis.domain.service.EvaluadorCasoExperimental;

public class ServicioEvaluacionExperimental {
    private final CatalogoCasosExperimentales catalogo;
    private final RepositorioEvaluaciones repositorio;
    private final ServicioAnalisisHibrido analizador;
    private final Executor ejecutor;
    private final Map<String, String> configuracion;
    private final AtomicBoolean ocupado = new AtomicBoolean();
    private final EvaluadorCasoExperimental evaluador = new EvaluadorCasoExperimental();
    public ServicioEvaluacionExperimental(CatalogoCasosExperimentales catalogo, RepositorioEvaluaciones repositorio,
            ServicioAnalisisHibrido analizador, Executor ejecutor, Map<String, String> configuracion) {
        this.catalogo = catalogo;
        this.repositorio = repositorio;
        this.analizador = analizador;
        this.ejecutor = ejecutor;
        this.configuracion = Map.copyOf(configuracion);
        recuperarInterrumpidas();
    }
    public EvaluacionExperimental.Resumen iniciar(List<String> identificadores) {
        if (!ocupado.compareAndSet(false, true)) throw new ExcepcionEvaluacion(Motivo.OCUPADO, "Ya existe una evaluacion en curso");
        EvaluacionExperimental inicial = null;
        try {
            CatalogoCasosExperimentales.Catalogo registro = catalogo.cargar();
            List<CasoExperimental> seleccion = seleccionar(registro.casos(), identificadores);
            Map<String, String> trazabilidad = new TreeMap<>(configuracion);
            trazabilidad.putAll(registro.integridad());
            trazabilidad.put("politicaEvaluacion", EvaluadorCasoExperimental.POLITICA);
            trazabilidad.put("politicaDuracion", "Tiempo mural desde la aceptacion; si se interrumpe incluye el intervalo hasta su recuperacion. Tiempos efectivos por caso en resultadosOriginales.tiempos");
            trazabilidad.put("limitacionMuestra", "Muestra intencional; variantes del mismo grupoOrigen no son observaciones independientes");
            inicial = new EvaluacionExperimental(UUID.randomUUID(), Estado.PENDIENTE, Instant.now(), null,
                    seleccion, List.of(), trazabilidad, null);
            repositorio.crear(inicial);
            EvaluacionExperimental tarea = inicial;
            ejecutor.execute(() -> ejecutar(tarea));
            return inicial.resumen();
        } catch (RuntimeException excepcion) {
            ocupado.set(false);
            if (inicial != null) repositorio.guardar(cambiar(inicial, Estado.FALLIDA, inicial.resultados(), excepcion.getMessage()));
            throw excepcion;
        }
    }
    private List<CasoExperimental> seleccionar(List<CasoExperimental> casos, List<String> identificadores) {
        if (identificadores == null || identificadores.isEmpty()) return casos;
        Set<String> solicitados = new LinkedHashSet<>(identificadores);
        if (solicitados.contains(null) || solicitados.size() != identificadores.size()) {
            throw new ExcepcionEvaluacion(Motivo.SOLICITUD_INVALIDA, "Los identificadores deben ser unicos y no nulos");
        }
        Set<String> disponibles = new HashSet<>(casos.stream().map(CasoExperimental::identificador).toList());
        if (!disponibles.containsAll(solicitados)) throw new ExcepcionEvaluacion(Motivo.SOLICITUD_INVALIDA, "Se solicitaron casos inexistentes");
        return casos.stream().filter(caso -> solicitados.contains(caso.identificador())).toList();
    }
    private void ejecutar(EvaluacionExperimental inicial) {
        EvaluacionExperimental actual = inicial;
        try {
            actual = cambiar(actual, Estado.EN_PROCESO, actual.resultados(), null);
            repositorio.guardar(actual);
            for (CasoExperimental caso : actual.casosSolicitados()) {
                if (Thread.currentThread().isInterrupted()) throw new IllegalStateException("Ejecucion interrumpida");
                ResultadoCasoExperimental resultado = procesar(caso);
                List<ResultadoCasoExperimental> resultados = new ArrayList<>(actual.resultados());
                resultados.add(resultado);
                actual = cambiar(actual, Estado.EN_PROCESO, resultados, null);
                repositorio.guardar(actual);
            }
            boolean errores = actual.resultados().stream().anyMatch(resultado -> !resultado.comparable());
            actual = cambiar(actual, errores ? Estado.COMPLETADA_CON_ERRORES : Estado.COMPLETADA, actual.resultados(), null);
            repositorio.guardar(actual);
        } catch (RuntimeException excepcion) {
            Estado estado = Thread.currentThread().isInterrupted() ? Estado.INTERRUMPIDA : Estado.FALLIDA;
            repositorio.guardar(cambiar(actual, estado, actual.resultados(), excepcion.getClass().getSimpleName() + ": " + excepcion.getMessage()));
        } finally { ocupado.set(false); }
    }
    private ResultadoCasoExperimental procesar(CasoExperimental caso) {
        long inicio = System.nanoTime();
        try (InputStream zip = catalogo.abrir(caso)) {
            return evaluador.evaluar(caso, analizador.analizar(caso.identificador() + ".zip", zip));
        } catch (Exception excepcion) {
            return evaluador.fallido(caso, excepcion.getClass().getSimpleName() + ": " + excepcion.getMessage(),
                    (System.nanoTime() - inicio) / 1_000_000);
        }
    }
    public EvaluacionExperimental consultar(UUID id) {
        return repositorio.buscar(id).orElseThrow(() -> new ExcepcionEvaluacion(Motivo.NO_ENCONTRADO, "Evaluacion inexistente"));
    }
    private void recuperarInterrumpidas() {
        for (EvaluacionExperimental evaluacion : repositorio.listar()) {
            if (!evaluacion.estado().finalizado()) repositorio.guardar(cambiar(evaluacion, Estado.INTERRUMPIDA,
                    evaluacion.resultados(), "La aplicacion termino antes de completar esta evaluacion; no se reanuda automaticamente. La fecha final indica la recuperacion y la duracion mural incluye el intervalo hasta el reinicio"));
        }
    }
    private EvaluacionExperimental cambiar(EvaluacionExperimental base, Estado estado,
            List<ResultadoCasoExperimental> resultados, String error) {
        return new EvaluacionExperimental(base.identificador(), estado, base.fechaInicio(),
                estado.finalizado() ? Instant.now() : null, base.casosSolicitados(), resultados, base.reproducibilidad(), error);
    }
}
