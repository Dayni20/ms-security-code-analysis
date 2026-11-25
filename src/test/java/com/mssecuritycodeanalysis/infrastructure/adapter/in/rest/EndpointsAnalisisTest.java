package com.mssecuritycodeanalysis.infrastructure.adapter.in.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.mssecuritycodeanalysis.application.port.out.AnalizadorEstatico;
import com.mssecuritycodeanalysis.application.port.out.AnalizadorIA;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisIA;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisIA.Motivo;
import com.mssecuritycodeanalysis.domain.model.ArchivoFuente;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisEstatico;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisIA;
import com.mssecuritycodeanalysis.infrastructure.config.PropiedadesOllama;

@SpringBootTest
@AutoConfigureMockMvc
class EndpointsAnalisisTest {

    @TempDir
    static Path temporales;

    @Autowired
    private MockMvc mvc;

    @Autowired
    private PropiedadesOllama propiedades;

    @MockitoBean
    private AnalizadorIA analizadorIA;

    @MockitoBean
    private AnalizadorEstatico analizadorEstatico;

    @DynamicPropertySource
    static void configurarTemporales(DynamicPropertyRegistry registro) {
        registro.add("proyecto.carga.directorio-temporal", () -> temporales.toString());
    }

    @Test
    void arrancaConLaConfiguracionLocalEsperada() {
        assertThat(propiedades.isConfiguracionValida()).isTrue();
        assertThat(propiedades.contexto()).isEqualTo(4096);
        assertThat(propiedades.timeoutRespuestaSegundos()).isEqualTo(300);
    }

    @Test
    void mantieneElEndpointDeSalud() throws Exception {
        mvc.perform(get("/api/v1/health")).andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.service").value("ms-security-code-analysis"));
    }

    @Test
    void mantieneCargaMultilenguajeYExclusionesSinDevolverContenido() throws Exception {
        mvc.perform(multipart("/api/v1/analysis/upload").file(zip("src/a.ts", "const dato = 1;")))
                .andExpect(status().isOk()).andExpect(jsonPath("$.cantidadArchivosFuente").value(1))
                .andExpect(jsonPath("$.archivos[0].rutaRelativa").value("src/a.ts"))
                .andExpect(jsonPath("$.archivos[0].lenguaje").value("TypeScript"))
                .andExpect(jsonPath("$.archivos[0].contenido").doesNotExist());
        comprobarLimpieza();
    }

    @Test
    void reutilizaCargaParaElNuevoEndpoint() throws Exception {
        when(analizadorIA.analizar(anyList())).thenAnswer(invocacion -> {
            List<ArchivoFuente> archivos = invocacion.getArgument(0);
            assertThat(archivos).singleElement().satisfies(archivo -> {
                assertThat(archivo.rutaRelativa()).isEqualTo("src/a.py");
                assertThat(archivo.contenido()).isEqualTo("print('hola')");
            });
            return resultado("COMPLETADO");
        });
        mvc.perform(multipart("/api/v1/analysis/ai").file(zip("src/a.py", "print('hola')")))
                .andExpect(status().isOk()).andExpect(jsonPath("$.nombreArchivoZip").value("proyecto.zip"))
                .andExpect(jsonPath("$.estado").value("COMPLETADO"))
                .andExpect(jsonPath("$.resultado.hallazgos").isEmpty())
                .andExpect(jsonPath("$.resultado.metodoDeteccion").value("IA"));
        comprobarLimpieza();
    }

    @ParameterizedTest
    @CsvSource({"NO_DISPONIBLE,503", "MODELO_NO_ENCONTRADO,503", "TIEMPO_AGOTADO,504",
            "RESPUESTA_INVALIDA,502", "GENERACION_INCOMPLETA,502", "COMUNICACION_FALLIDA,502",
            "SIN_COBERTURA,422", "FRAGMENTACION_INVALIDA,422"})
    void comunicaErroresSinPresentarlosComoAnalisisExitosos(Motivo motivo, int estado) throws Exception {
        when(analizadorIA.analizar(anyList())).thenThrow(new ExcepcionAnalisisIA("Fallo controlado", motivo,
                null, resultado("INCOMPLETO")));
        mvc.perform(multipart("/api/v1/analysis/ai").file(zip("a.py", "pass")))
                .andExpect(status().is(estado)).andExpect(jsonPath("$.estado").value("INCOMPLETO"))
                .andExpect(jsonPath("$.motivo").value(motivo.name()))
                .andExpect(jsonPath("$.resultado.estado").value("INCOMPLETO"));
        comprobarLimpieza();
    }

    @Test
    void rechazaZipSlipAntesDeEnviarCodigoAlAnalizador() throws Exception {
        mvc.perform(multipart("/api/v1/analysis/ai").file(zip("../a.py", "pass"))).andExpect(status().isBadRequest());
        verifyNoInteractions(analizadorIA);
        comprobarLimpieza();
    }

    @Test
    void rechazaArchivoFaltanteOVacio() throws Exception {
        mvc.perform(multipart("/api/v1/analysis/ai")).andExpect(status().isBadRequest());
        mvc.perform(multipart("/api/v1/analysis/ai").file(new MockMultipartFile("file", "proyecto.zip",
                "application/zip", new byte[0]))).andExpect(status().isBadRequest());
        verifyNoInteractions(analizadorIA);
    }

    @Test
    void mantieneElContratoDelEndpointEstatico() throws Exception {
        when(analizadorEstatico.analizar(anyList())).thenReturn(new ResultadoAnalisisEstatico(List.of(),
                List.of("Python"), List.of("Python"), List.of(), List.of("a.py"), "1.187.0", "huella"));
        mvc.perform(multipart("/api/v1/analysis/static").file(zip("a.py", "pass")))
                .andExpect(status().isOk()).andExpect(jsonPath("$.estado").value("COMPLETADO"))
                .andExpect(jsonPath("$.resultado.versionSemgrep").value("1.187.0"));
        comprobarLimpieza();
    }

    private MockMultipartFile zip(String ruta, String contenido) throws Exception {
        ByteArrayOutputStream salida = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(salida)) {
            zip.putNextEntry(new ZipEntry(ruta));
            zip.write(contenido.getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
            zip.putNextEntry(new ZipEntry("node_modules/ignorado.js"));
            zip.write("codigo de terceros".getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
        }
        return new MockMultipartFile("file", "proyecto.zip", "application/zip", salida.toByteArray());
    }

    private ResultadoAnalisisIA resultado(String estado) {
        return new ResultadoAnalisisIA(estado, List.of(), List.of("src/a.py"), List.of("Python"), List.of("Python"),
                List.of(), "qwen2.5-coder:7b-instruct", "digest", new ResultadoAnalisisIA.ParametrosGeneracion(
                        0, 4096, 1024, 0, 80, 4000, 10, 512, 200), "seguridad-cwe-v1", "huella", "IA", List.of(), List.of());
    }

    private void comprobarLimpieza() throws Exception {
        try (java.util.stream.Stream<Path> archivos = Files.list(temporales)) {
            assertThat(archivos).isEmpty();
        }
    }
}
