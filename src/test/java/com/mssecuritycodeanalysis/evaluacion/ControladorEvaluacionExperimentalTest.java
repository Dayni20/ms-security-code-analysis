package com.mssecuritycodeanalysis.evaluacion;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static com.mssecuritycodeanalysis.evaluacion.DatosEvaluacion.*;
import java.io.ByteArrayInputStream;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import com.mssecuritycodeanalysis.application.port.out.*;
import com.mssecuritycodeanalysis.application.service.*;
import com.mssecuritycodeanalysis.infrastructure.adapter.out.evaluacion.RepositorioEvaluacionesJson;
import com.mssecuritycodeanalysis.infrastructure.adapter.in.rest.ControladorEvaluacionExperimental;
import com.mssecuritycodeanalysis.infrastructure.adapter.in.rest.excepcion.ManejadorErroresEvaluacion;

class ControladorEvaluacionExperimentalTest {
    @TempDir Path temporal;
    private MockMvc mvc;
    private ServicioEvaluacionExperimental servicio;
    private final List<Runnable> pendientes = new ArrayList<>();
    @BeforeEach
    void preparar() {
        CatalogoCasosExperimentales catalogo = mock(CatalogoCasosExperimentales.class);
        when(catalogo.cargar()).thenReturn(new CatalogoCasosExperimentales.Catalogo(List.of(caso("Uno", true)), Map.of()));
        when(catalogo.abrir(any())).thenReturn(new ByteArrayInputStream(new byte[]{1}));
        LectorProyectoFuente lector = entrada -> List.of(new com.mssecuritycodeanalysis.domain.model.ArchivoFuente(RUTA, "class Unidad {}", "Java"));
        AnalizadorEstatico estatico = archivos -> estatico(List.of());
        AnalizadorIA ia = archivos -> ia(List.of());
        servicio = new ServicioEvaluacionExperimental(catalogo, new RepositorioEvaluacionesJson(temporal, MAPPER),
                new ServicioAnalisisHibrido(new ServicioCargaProyectoFuente(lector), estatico, ia), pendientes::add, Map.of());
        mvc = MockMvcBuilders.standaloneSetup(new ControladorEvaluacionExperimental(servicio))
                .setControllerAdvice(new ManejadorErroresEvaluacion()).build();
    }
    @Test
    void iniciaConsultaExportaYRecuperaResultados() throws Exception {
        String respuesta = mvc.perform(post("/api/v1/evaluation/run").contentType(MediaType.APPLICATION_JSON).content("{\"identificadores\":[\"Uno\"]}"))
                .andExpect(status().isAccepted()).andExpect(header().exists("Location"))
                .andExpect(jsonPath("$.estado").value("PENDIENTE")).andReturn().getResponse().getContentAsString();
        String id = MAPPER.readTree(respuesta).path("identificador").asText();
        mvc.perform(post("/api/v1/evaluation/run")).andExpect(status().isConflict());
        mvc.perform(get("/api/v1/evaluation/{id}", id)).andExpect(status().isOk()).andExpect(jsonPath("$.casosProcesados").value(0));
        mvc.perform(get("/api/v1/evaluation/{id}/export", id)).andExpect(status().isConflict());
        pendientes.removeFirst().run();
        mvc.perform(get("/api/v1/evaluation/{id}", id)).andExpect(status().isOk()).andExpect(jsonPath("$.porcentajeAvance").value(100))
                .andExpect(jsonPath("$.comparacionPrincipal.ESTATICO.GLOBAL.falsosNegativos").value(1));
        mvc.perform(get("/api/v1/evaluation/{id}/results", id)).andExpect(status().isOk())
                .andExpect(jsonPath("$.resultados[0].caso.clasificacionEsperada").value("VULNERABLE"))
                .andExpect(jsonPath("$.resultados[0].resultadosOriginales.ia.resultado.modelo").value("qwen2.5-coder:7b-instruct"));
        String csv = mvc.perform(get("/api/v1/evaluation/{id}/export", id)).andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("text/csv"))
                .andExpect(header().string("Content-Disposition", org.hamcrest.Matchers.containsString("attachment")))
                .andReturn().getResponse().getContentAsString(java.nio.charset.StandardCharsets.UTF_8);
        assertThat(csv).contains("COMPARACION_PRINCIPAL", "DISPONIBLES_POR_METODO", "CWE-23", "CWE-22", "NO_DISPONIBLE");
        assertThat(csv).doesNotContain("NaN", "Infinity");
        assertThat(new RepositorioEvaluacionesJson(temporal, MAPPER).buscar(UUID.fromString(id))).isPresent();
    }
    @Test
    void validaPeticionesYRecursoInexistente() throws Exception {
        mvc.perform(post("/api/v1/evaluation/run").contentType(MediaType.APPLICATION_JSON).content("{\"identificadores\":[\"NoExiste\"]}"))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/api/v1/evaluation/run").contentType(MediaType.APPLICATION_JSON).content("{"))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/api/v1/evaluation/run").contentType(MediaType.APPLICATION_JSON).content("{\"ids\":[\"Uno\"]}"))
                .andExpect(status().isBadRequest());
        mvc.perform(get("/api/v1/evaluation/no-uuid")).andExpect(status().isBadRequest());
        mvc.perform(get("/api/v1/evaluation/{id}", UUID.randomUUID())).andExpect(status().isNotFound());
        mvc.perform(get("/api/v1/evaluation/{id}/results", UUID.randomUUID())).andExpect(status().isNotFound());
        mvc.perform(get("/api/v1/evaluation/{id}/export", UUID.randomUUID())).andExpect(status().isNotFound());
    }
    @Test
    void csvEscapaComillasYFormulasYMarcaCasosNoProcesados() {
        com.mssecuritycodeanalysis.domain.service.EvaluadorCasoExperimental evaluador = new com.mssecuritycodeanalysis.domain.service.EvaluadorCasoExperimental();
        var caso = caso("Uno", true);
        var fallo = evaluador.fallido(caso, "=mensaje,\"dato\"\nsegunda linea", 10);
        var evaluacion = new com.mssecuritycodeanalysis.domain.model.evaluacion.EvaluacionExperimental(UUID.randomUUID(),
                com.mssecuritycodeanalysis.domain.model.evaluacion.EvaluacionExperimental.Estado.INTERRUMPIDA,
                java.time.Instant.now(), java.time.Instant.now(), List.of(caso, caso("Dos", false)), List.of(fallo), Map.of(), "Interrupcion");
        String csv = new String(new com.mssecuritycodeanalysis.infrastructure.adapter.in.rest.ExportadorEvaluacionCsv().exportar(evaluacion),
                java.nio.charset.StandardCharsets.UTF_8);
        assertThat(csv).startsWith("\ufeff");
        assertThat(csv).contains("'=mensaje,\"\"dato\"\"", "Caso no procesado", "NO_EVALUABLE", "INTERRUMPIDA");
    }

}
