package com.mssecuritycodeanalysis.evaluacion;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verify;
import static org.mockito.ArgumentMatchers.any;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import com.mssecuritycodeanalysis.application.port.out.AnalizadorEstatico;
import com.mssecuritycodeanalysis.application.port.out.AnalizadorIA;
import com.mssecuritycodeanalysis.infrastructure.config.PropiedadesEvaluacion;

@SpringBootTest
@AutoConfigureMockMvc
class RutasEvaluacionWebTest {
    @TempDir static Path temporal;
    @Autowired MockMvc mvc;
    @Autowired PropiedadesEvaluacion propiedades;
    @MockitoBean AnalizadorEstatico estatico;
    @MockitoBean AnalizadorIA ia;
    @MockitoBean(name = "ejecutorEvaluacion") java.util.concurrent.ExecutorService ejecutor;
    @DynamicPropertySource
    static void configurar(DynamicPropertyRegistry registro) {
        registro.add("evaluacion.directorio-resultados", () -> temporal.resolve("resultados").toString());
    }
    @Test
    void leeCatalogoRealConEnlaceDePropiedadesWebSinResolverContraTomcat() throws Exception {
        Assumptions.assumeTrue(Files.isRegularFile(Path.of("configuracion-experimental/casos-prueba.json")));
        assertThat(propiedades.raizProyecto()).isEqualTo(".");
        assertThat(propiedades.catalogo()).isEqualTo("configuracion-experimental/casos-prueba.json");
        mvc.perform(post("/api/v1/evaluation/run").contentType(MediaType.APPLICATION_JSON)
                .content("{\"identificadores\":[\"CasoInexistenteComprobacion\"]}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Se solicitaron casos inexistentes"));
        mvc.perform(post("/api/v1/evaluation/run").contentType(MediaType.APPLICATION_JSON)
                .content("{\"identificadores\":[\"Caso001\",\"Caso003\"]}"))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.estado").value("PENDIENTE"))
                .andExpect(jsonPath("$.casosSolicitados").value(2));
        verify(ejecutor).execute(any(Runnable.class));
        verifyNoInteractions(estatico, ia);
    }
}
