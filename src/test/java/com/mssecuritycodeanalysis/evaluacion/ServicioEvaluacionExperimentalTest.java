package com.mssecuritycodeanalysis.evaluacion;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static com.mssecuritycodeanalysis.evaluacion.DatosEvaluacion.*;
import java.io.ByteArrayInputStream;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import com.mssecuritycodeanalysis.application.port.out.*;
import com.mssecuritycodeanalysis.application.service.*;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionEvaluacion;
import com.mssecuritycodeanalysis.domain.model.*;
import com.mssecuritycodeanalysis.domain.model.evaluacion.*;
import com.mssecuritycodeanalysis.infrastructure.adapter.out.evaluacion.RepositorioEvaluacionesJson;

class ServicioEvaluacionExperimentalTest {
    @TempDir Path temporal;
    private CatalogoCasosExperimentales catalogo;
    private RepositorioEvaluacionesJson repositorio;
    private LectorProyectoFuente lector;
    private AnalizadorEstatico estatico;
    private AnalizadorIA ia;
    private final List<Runnable> pendientes = new ArrayList<>();
    @BeforeEach
    void preparar() {
        catalogo = mock(CatalogoCasosExperimentales.class);
        repositorio = new RepositorioEvaluacionesJson(temporal, MAPPER);
        lector = mock(LectorProyectoFuente.class);
        estatico = mock(AnalizadorEstatico.class);
        ia = mock(AnalizadorIA.class);
        when(catalogo.cargar()).thenReturn(new CatalogoCasosExperimentales.Catalogo(List.of(caso("Uno", true), caso("Dos", false)), Map.of("sha256Catalogo", "simulado")));
        when(catalogo.abrir(any())).thenAnswer(invocacion -> new ByteArrayInputStream(new byte[]{1}));
        List<ArchivoFuente> archivos = List.of(new ArchivoFuente(RUTA, "class Unidad {}", "Java"));
        when(lector.leer(any())).thenReturn(archivos);
        when(estatico.analizar(anyList())).thenReturn(estatico(List.of()));
        when(ia.analizar(anyList())).thenReturn(ia(List.of()));
    }
    private ServicioEvaluacionExperimental servicio(java.util.concurrent.Executor ejecutor) {
        return new ServicioEvaluacionExperimental(catalogo, repositorio,
                new ServicioAnalisisHibrido(new ServicioCargaProyectoFuente(lector), estatico, ia), ejecutor, Map.of("modelo", "7b"));
    }
    @Test
    void seleccionaTodosOUnSubconjuntoYReutilizaAnalisisSinEntregarReferencias() throws Exception {
        ServicioEvaluacionExperimental servicio = servicio(pendientes::add);
        EvaluacionExperimental.Resumen inicio = servicio.iniciar(List.of("Uno"));
        assertThat(inicio.estado()).isEqualTo(EvaluacionExperimental.Estado.PENDIENTE);
        assertThatThrownBy(() -> servicio.iniciar(null)).isInstanceOf(ExcepcionEvaluacion.class).hasMessageContaining("en curso");
        assertThat(servicio.consultar(inicio.identificador()).resultados()).isEmpty();
        pendientes.removeFirst().run();
        EvaluacionExperimental finalizada = servicio.consultar(inicio.identificador());
        assertThat(finalizada.estado()).isEqualTo(EvaluacionExperimental.Estado.COMPLETADA);
        assertThat(finalizada.resultados()).hasSize(1);
        verify(lector, times(1)).leer(any());
        org.mockito.ArgumentCaptor<List<com.mssecuritycodeanalysis.domain.model.ArchivoFuente>> captor = org.mockito.ArgumentCaptor.captor();
        verify(estatico, times(1)).analizar(captor.capture());
        verify(ia, times(1)).analizar(captor.getValue());
        ArchivoFuente entregado = captor.getValue().getFirst();
        assertThat(entregado.rutaRelativa()).isEqualTo(RUTA);
        assertThat(entregado.contenido()).doesNotContain("VULNERABLE", "CWE", "original", "clasificacionEsperada");
        EvaluacionExperimental.Resumen todos = servicio.iniciar(null);
        assertThat(todos.casosSolicitados()).isEqualTo(2);
        pendientes.removeFirst().run();
        assertThat(repositorio.listar()).hasSize(2);
        assertThat(new RepositorioEvaluacionesJson(temporal, MAPPER).buscar(inicio.identificador())).contains(finalizada);
    }
    @Test
    void rechazaSeleccionInvalidaYSigueDisponible() {
        ServicioEvaluacionExperimental servicio = servicio(pendientes::add);
        assertThatThrownBy(() -> servicio.iniciar(List.of("Ausente"))).isInstanceOf(ExcepcionEvaluacion.class);
        assertThatThrownBy(() -> servicio.iniciar(List.of("Uno", "Uno"))).isInstanceOf(ExcepcionEvaluacion.class);
        assertThat(servicio.iniciar(List.of()).casosSolicitados()).isEqualTo(2);
    }
    @Test
    void continuaConOtrosCasosAnteFalloTecnico() {
        when(ia.analizar(anyList())).thenThrow(new IllegalStateException("simulado")).thenReturn(ia(List.of()));
        ServicioEvaluacionExperimental servicio = servicio(Runnable::run);
        UUID id = servicio.iniciar(null).identificador();
        EvaluacionExperimental.Resumen resumen = servicio.consultar(id).resumen();
        assertThat(resumen.estado()).isEqualTo(EvaluacionExperimental.Estado.COMPLETADA_CON_ERRORES);
        assertThat(resumen.casosProcesados()).isEqualTo(2);
        assertThat(resumen.casosExitosos()).isEqualTo(1);
        assertThat(resumen.comparacionPrincipal().get(ResultadoCasoExperimental.Metodo.ESTATICO).get("GLOBAL").total()).isEqualTo(1);
    }
    @Test
    void recuperaInterrumpidasSinReejecutarAnalizadores() {
        UUID id = UUID.randomUUID();
        repositorio.crear(new EvaluacionExperimental(id, EvaluacionExperimental.Estado.EN_PROCESO, Instant.now(), null,
                List.of(caso("Uno", true)), List.of(), Map.of(), null));
        ServicioEvaluacionExperimental servicio = servicio(pendientes::add);
        assertThat(servicio.consultar(id).estado()).isEqualTo(EvaluacionExperimental.Estado.INTERRUMPIDA);
        verifyNoInteractions(estatico, ia);
        assertThat(servicio.consultar(id).error()).contains("no se reanuda");
    }
    @Test
    void consultaProgresoMientrasCorreEnOtroHilo() throws Exception {
        CountDownLatch iniciado = new CountDownLatch(1);
        CountDownLatch continuar = new CountDownLatch(1);
        when(ia.analizar(anyList())).thenAnswer(invocacion -> {
            iniciado.countDown();
            if (!continuar.await(5, TimeUnit.SECONDS)) throw new IllegalStateException("Prueba bloqueada");
            return ia(List.of());
        });
        ExecutorService ejecutor = Executors.newSingleThreadExecutor();
        try {
            ServicioEvaluacionExperimental servicio = servicio(ejecutor);
            UUID id = servicio.iniciar(List.of("Uno")).identificador();
            assertThat(iniciado.await(5, TimeUnit.SECONDS)).isTrue();
            assertThat(servicio.consultar(id).estado()).isEqualTo(EvaluacionExperimental.Estado.EN_PROCESO);
            assertThat(servicio.consultar(id).resumen().porcentajeAvance()).isZero();
            continuar.countDown();
            ejecutor.shutdown();
            assertThat(ejecutor.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
            assertThat(servicio.consultar(id).resumen().porcentajeAvance()).isEqualTo(100);
        } finally { continuar.countDown(); ejecutor.shutdownNow(); }
    }
    @Test
    void noSobrescribeEjecucionesYExponeArchivosCorruptos() throws Exception {
        ServicioEvaluacionExperimental servicio = servicio(Runnable::run);
        UUID id = servicio.iniciar(List.of("Uno")).identificador();
        EvaluacionExperimental original = servicio.consultar(id);
        assertThatThrownBy(() -> repositorio.crear(original)).isInstanceOf(ExcepcionEvaluacion.class);
        assertThat(servicio.consultar(id)).isEqualTo(original);
        java.nio.file.Files.writeString(temporal.resolve(id.toString()).resolve("evaluacion.json"), "{");
        assertThatThrownBy(() -> servicio.consultar(id)).isInstanceOf(ExcepcionEvaluacion.class).hasMessageContaining("leer o guardar");
    }
    @Test
    void registraFalloDeAperturaDelCasoSinLlamarAnalizadores() {
        when(catalogo.abrir(any())).thenThrow(new IllegalStateException("Integridad incorrecta"));
        ServicioEvaluacionExperimental servicio = servicio(Runnable::run);
        UUID id = servicio.iniciar(List.of("Uno")).identificador();
        ResultadoCasoExperimental resultado = servicio.consultar(id).resultados().getFirst();
        assertThat(resultado.comparable()).isFalse();
        assertThat(resultado.falloTecnico()).contains("Integridad incorrecta");
        verifyNoInteractions(lector, estatico, ia);
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.EnumSource(value = com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisIA.Motivo.class,
            names = {"TIEMPO_AGOTADO", "RESPUESTA_INVALIDA", "COMUNICACION_FALLIDA", "MODELO_NO_ENCONTRADO"})
    void registraMotivosTecnicosSinContarlosComoFalsosNegativos(
            com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisIA.Motivo motivo) {
        when(ia.analizar(anyList())).thenThrow(new com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisIA("Fallo simulado", motivo));
        ServicioEvaluacionExperimental servicio = servicio(Runnable::run);
        UUID id = servicio.iniciar(List.of("Uno")).identificador();
        EvaluacionExperimental evaluacion = servicio.consultar(id);
        assertThat(evaluacion.resultados().getFirst().resultadosOriginales().ia().motivo()).isEqualTo(motivo.name());
        assertThat(evaluacion.resumen().comparacionPrincipal().get(ResultadoCasoExperimental.Metodo.IA).get("GLOBAL").total()).isZero();
        assertThat(evaluacion.resumen().comparacionPrincipal().get(ResultadoCasoExperimental.Metodo.IA).get("GLOBAL").falsosNegativos()).isZero();
    }

}
