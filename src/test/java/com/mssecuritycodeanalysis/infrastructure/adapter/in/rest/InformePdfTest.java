package com.mssecuritycodeanalysis.infrastructure.adapter.in.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.rendering.PDFRenderer;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mssecuritycodeanalysis.application.service.ServicioInformePdf;
import com.mssecuritycodeanalysis.domain.model.HallazgoHibrido;
import com.mssecuritycodeanalysis.domain.model.HallazgoHibrido.*;
import com.mssecuritycodeanalysis.domain.model.HallazgoSeguridad;
import com.mssecuritycodeanalysis.domain.model.InformeAnalisis;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisEstatico;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisHibrido;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisHibrido.*;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisIA;
import com.mssecuritycodeanalysis.infrastructure.adapter.out.pdf.GeneradorInformePdfBox;

class InformePdfTest {
    private final ObjectMapper mapper = new ObjectMapper();
    private MockMvc mvc;

    @BeforeEach
    void preparar() {
        mvc = MockMvcBuilders.standaloneSetup(new ControladorInformePdf(
                new ServicioInformePdf(new GeneradorInformePdfBox()), new LectorSolicitudInforme(mapper))).build();
    }

    private HallazgoSeguridad hallazgo() {
        return new HallazgoSeguridad("regla", "Posible inyección SQL: revisión de parámetros, acción y contraseña.",
                List.of("CWE-89"), "módulo/área/Consulta.java", 16, "ALTO", "ESTATICO");
    }

    private ResultadoAnalisisEstatico estatico() {
        return new ResultadoAnalisisEstatico(List.of(hallazgo()), List.of("Java"), List.of("Java"),
                List.of(), List.of("módulo/área/Consulta.java"), "1.187.0", "sha-reglas");
    }

    private ResultadoAnalisisIA ia() {
        return new ResultadoAnalisisIA("COMPLETADO", List.of(), List.of("a.java"), List.of("Java"), List.of("Java"), List.of(),
                "qwen2.5-coder:3b-instruct", "digest-123", new ResultadoAnalisisIA.ParametrosGeneracion(0, 4096, 1024,
                        0, 80, 4000, 10, 512, 200), "prompt-v3", "sha-prompt", "IA", List.of(), List.of("Limitación entre archivos"));
    }

    private ResultadoAnalisisHibrido hibrido() {
        List<HallazgoHibrido> hallazgos = List.of(EstadoRevision.values()).stream().map(estado -> new HallazgoHibrido(
                estado.name(), "a.java", "CWE-89", 16, "Descripción extensa de la posible inyección", "ALTO", Procedencia.AMBOS,
                EstadoCorrelacion.MISMA_OPERACION, estado, "Justificación verificable de la revisión",
                List.of(new Evidencia(TipoEvidencia.OPERACION, 16, 16, "Operación sensible observada")), List.of(hallazgo()))).toList();
        CoberturaAnalizador cobertura = new CoberturaAnalizador(List.of("Java"), List.of("Java"), List.of(), List.of(), List.of("a.java"), List.of());
        return new ResultadoAnalisisHibrido("PARCIAL", new ResultadoMetodo<>("COMPLETADO", estatico(), null, null, 100, cobertura),
                new ResultadoMetodo<>("PARCIAL", ia(), "TIEMPO_AGOTADO", "Tiempo agotado en otro fragmento", 500, cobertura), hallazgos,
                List.of("a.java"), List.of("a.java"), new TiemposEjecucion(10, 100, 500, 10, 620, false),
                "correlacion-v1", List.of("Misma operación identificada"), List.of("No confirma explotabilidad"));
    }

    private ObjectNode solicitud(String metodo) {
        Object resultado = switch (metodo) { case "static" -> estatico(); case "ai" -> ia(); default -> hibrido(); };
        ObjectNode respuesta = mapper.createObjectNode().put("nombreArchivoZip", "proyecto-áé.zip")
                .put("estado", metodo.equals("hybrid") ? "PARCIAL" : "COMPLETADO");
        respuesta.set("resultado", mapper.valueToTree(resultado));
        ObjectNode solicitud = mapper.createObjectNode().put("metodo", metodo).put("nombreArchivoZip", "proyecto-áé.zip")
                .put("fechaAnalisis", "2026-11-25T05:30:00Z").put("tiempoSolicitudMilisegundos", 1234);
        solicitud.set("respuesta", respuesta);
        return solicitud;
    }

    @ParameterizedTest
    @ValueSource(strings = {"static", "ai", "hybrid"})
    void descargaLosTresMetodosSinInvocarAnalizadores(String metodo) throws Exception {
        var respuesta = mvc.perform(post("/api/v1/analysis/report/pdf").contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsBytes(solicitud(metodo)))).andExpect(status().isOk()).andReturn().getResponse();
        assertThat(respuesta.getContentType()).isEqualTo("application/pdf");
        assertThat(respuesta.getHeader("Content-Disposition")).contains("attachment", "informe-seguridad.pdf");
        if (metodo.equals("hybrid")) {
            Path directorio = Path.of("build", "verificacion-pdf");
            Files.createDirectories(directorio);
            Files.write(directorio.resolve("informe-hibrido.pdf"), respuesta.getContentAsByteArray());
        }
        try (PDDocument pdf = Loader.loadPDF(respuesta.getContentAsByteArray())) {
            String texto = new PDFTextStripper().getText(pdf);
            assertThat(texto).contains("proyecto-áé.zip", "no son vulnerabilidades confirmadas", "Archivos analizados", "Alertas encontradas");
            assertThat(texto).doesNotContain("Digest", "SHA-256", "Temperatura", "Trazabilidad de fragmentos", "RF-08",
                    "Trazabilidad de correlación", "Limitaciones del método híbrido", "declarado por", "seguridad-cwe");
            if (metodo.equals("static")) assertThat(texto).contains("1.187.0", "parámetros", "contraseña").doesNotContain("sha-reglas");
            if (metodo.equals("ai")) assertThat(texto).contains("qwen2.5-coder", "no garantiza").doesNotContain("digest-123", "sha-prompt", "4096");
            if (metodo.equals("hybrid")) assertThat(texto).contains("Descartada con justificación", "Pendiente de revisión", "Respaldada por evidencia", "Justificación verificable", "Tiempo agotado");
            Path directorio = Path.of("build", "verificacion-pdf");
            Files.createDirectories(directorio);
            Files.write(directorio.resolve("informe-" + metodo + ".pdf"), respuesta.getContentAsByteArray());
            PDFRenderer renderer = new PDFRenderer(pdf);
            for (int pagina = 0; pagina < pdf.getNumberOfPages(); pagina++) {
                javax.imageio.ImageIO.write(renderer.renderImageWithDPI(pagina, 95), "PNG",
                        directorio.resolve(metodo + "-pagina-" + (pagina + 1) + ".png").toFile());
            }
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"metodo", "respuesta", "nombreArchivoZip"})
    void rechazaCamposObligatoriosAusentes(String campo) throws Exception {
        ObjectNode solicitud = solicitud("static");
        solicitud.remove(campo);
        mvc.perform(post("/api/v1/analysis/report/pdf").contentType(MediaType.APPLICATION_JSON)
                .content(solicitud.toString())).andExpect(status().isBadRequest());
    }

    @Test
    void rechazaLineasYFechasInvalidas() throws Exception {
        ObjectNode solicitud = solicitud("static");
        ((ObjectNode) solicitud.at("/respuesta/resultado/hallazgos/0")).put("linea", -1);
        mvc.perform(post("/api/v1/analysis/report/pdf").contentType(MediaType.APPLICATION_JSON)
                .content(solicitud.toString())).andExpect(status().isBadRequest());
        solicitud = solicitud("static").put("fechaAnalisis", "fecha falsa");
        mvc.perform(post("/api/v1/analysis/report/pdf").contentType(MediaType.APPLICATION_JSON)
                .content(solicitud.toString())).andExpect(status().isBadRequest());
    }

    @Test
    void rechazaJsonDuplicadoYTiposDeResultadoIncompatibles() throws Exception {
        mvc.perform(post("/api/v1/analysis/report/pdf").contentType(MediaType.APPLICATION_JSON)
                .content("{\"metodo\":\"static\",\"metodo\":\"ai\"}")).andExpect(status().isBadRequest());
        ObjectNode solicitud = solicitud("static").put("metodo", "ai");
        mvc.perform(post("/api/v1/analysis/report/pdf").contentType(MediaType.APPLICATION_JSON)
                .content(solicitud.toString())).andExpect(status().isBadRequest());
    }

    @Test
    void rechazaCuerpoExcesivoYParametrosNulos() throws Exception {
        mvc.perform(post("/api/v1/analysis/report/pdf").contentType(MediaType.APPLICATION_JSON)
                .content(" ".repeat(LectorSolicitudInforme.MAX_BYTES + 1))).andExpect(status().isBadRequest());
        ObjectNode solicitud = solicitud("ai");
        ((ObjectNode) solicitud.at("/respuesta/resultado")).putNull("parametros");
        mvc.perform(post("/api/v1/analysis/report/pdf").contentType(MediaType.APPLICATION_JSON)
                .content(solicitud.toString())).andExpect(status().isBadRequest());
    }

    @Test
    void conservaTextosExtensosEnVariasPaginasYRenderiza() throws Exception {
        String descripcion = "Inicio español ñ áéíóú ¿Qué operación? " + "Detalle de evidencia y propagación. ".repeat(1500) + " FIN-UNICO";
        HallazgoSeguridad largo = new HallazgoSeguridad("larga", descripcion, List.of("CWE-89"),
                "src/" + "ruta-sin-espacios".repeat(40) + ".java", 3, "MEDIO", "ESTATICO");
        ResultadoAnalisisEstatico datos = new ResultadoAnalisisEstatico(List.of(largo, hallazgo()),
                List.of("Java"), List.of("Java"), List.of(), List.of("a.java"), "1.187.0", "huella");
        byte[] contenido = new GeneradorInformePdfBox().generar(new InformeAnalisis(InformeAnalisis.Metodo.ESTATICO,
                "Proyecto con español", "COMPLETADO", Instant.parse("2026-11-25T05:30:00Z"), Instant.parse("2026-11-25T05:31:00Z"),
                1500L, null, null, datos, null, null));
        Path directorio = Path.of("build", "verificacion-pdf");
        Files.createDirectories(directorio);
        Files.write(directorio.resolve("informe-extenso.pdf"), contenido);
        try (PDDocument pdf = Loader.loadPDF(contenido)) {
            assertThat(pdf.getNumberOfPages()).isGreaterThan(2);
            assertThat(new PDFTextStripper().getText(pdf)).contains("FIN-UNICO", "contraseña", "ñ áéíóú");
            PDFRenderer renderer = new PDFRenderer(pdf);
            javax.imageio.ImageIO.write(renderer.renderImageWithDPI(0, 90), "PNG", directorio.resolve("pagina-1.png").toFile());
            javax.imageio.ImageIO.write(renderer.renderImageWithDPI(1, 90), "PNG", directorio.resolve("pagina-2.png").toFile());
            javax.imageio.ImageIO.write(renderer.renderImageWithDPI(pdf.getNumberOfPages() - 1, 90), "PNG", directorio.resolve("pagina-final.png").toFile());
        }
    }
}
