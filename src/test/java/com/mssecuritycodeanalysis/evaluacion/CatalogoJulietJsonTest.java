package com.mssecuritycodeanalysis.evaluacion;

import static org.assertj.core.api.Assertions.*;
import static com.mssecuritycodeanalysis.evaluacion.DatosEvaluacion.MAPPER;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.zip.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import com.fasterxml.jackson.databind.node.*;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionEvaluacion;
import com.mssecuritycodeanalysis.infrastructure.adapter.out.evaluacion.CatalogoJulietJson;

class CatalogoJulietJsonTest {
    @TempDir Path raiz;
    private ObjectNode registro;
    private ObjectNode caso;
    private final byte[] fuente = "package muestra;\nclass Unidad {\n void ejecutar() {}\n}\n".getBytes(StandardCharsets.UTF_8);
    @BeforeEach
    void prepararRegistroSimulado() throws Exception {
        Path carpeta = raiz.resolve("casos/Uno/src");
        Files.createDirectories(carpeta);
        Files.write(carpeta.resolve("Unidad.java"), fuente);
        Files.write(raiz.resolve("original.java"), fuente);
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(raiz.resolve("casos/Uno.zip")))) {
            zip.putNextEntry(new ZipEntry("src/Unidad.java")); zip.write(fuente); zip.closeEntry();
        }
        registro = MAPPER.createObjectNode();
        registro.put("dataset", "Registro simulado para pruebas");
        registro.put("sha256DistribucionOficial", "no-aplica-simulacion");
        registro.put("sha256ManifestOriginal", "no-aplica-simulacion");
        caso = registro.putArray("casos").addObject();
        caso.put("identificador", "Uno").put("archivoOriginal", "original.java")
                .put("archivoPreparado", "casos/Uno/src/Unidad.java").put("paqueteAnalisis", "casos/Uno.zip")
                .put("metodoOriginal", "entrada").put("cweOriginal", "CWE-23").put("cweNormalizado", "CWE-22")
                .put("clasificacionEsperada", "VULNERABLE").put("sha256Original", hash(fuente))
                .put("sha256Preparado", hash(fuente)).put("sha256PaqueteAnalisis", hash(Files.readAllBytes(raiz.resolve("casos/Uno.zip"))))
                .put("grupoOrigen", hash(fuente));
        caso.putArray("lineasVulnerabilidadOriginales").add(2);
        caso.putArray("lineasVulnerabilidadPreparadas").add(2);
        caso.putArray("lineasOperacionVulnerableOriginales").add(3);
        caso.putArray("lineasOperacionVulnerablePreparadas").add(3);
        caso.putArray("lineasOperacionSensibleOriginales").add(3);
        caso.putArray("lineasOperacionSensiblePreparadas").add(3);
        caso.putArray("anotacionesManifiesto").addObject().put("line", "2");
        caso.putArray("dependencias");
        ArrayNode correspondencia = caso.putArray("correspondenciaLineas");
        for (int linea = 1; linea <= 4; linea++) correspondencia.addObject().put("original", linea).put("preparada", linea);
    }
    private CatalogoJulietJson lector() throws Exception {
        MAPPER.writeValue(raiz.resolve("referencia.json").toFile(), registro);
        return new CatalogoJulietJson(raiz, Path.of("referencia.json"), MAPPER);
    }
    @Test
    void verificaIntegridadUbicacionesYContenidoDelZipSinAnalizarlo() throws Exception {
        CatalogoJulietJson lector = lector();
        var catalogo = lector.cargar();
        assertThat(catalogo.casos()).hasSize(1);
        assertThat(catalogo.casos().getFirst().rutaAnalizada()).isEqualTo("src/Unidad.java");
        try (InputStream zip = lector.abrir(catalogo.casos().getFirst())) { assertThat(zip.read()).isEqualTo('P'); }
        Files.write(raiz.resolve("casos/Uno.zip"), new byte[]{0});
        assertThatThrownBy(() -> lector.abrir(catalogo.casos().getFirst())).isInstanceOf(ExcepcionEvaluacion.class);
    }
    @ParameterizedTest
    @ValueSource(strings = {"duplicado", "cwe", "clasificacion", "linea", "huella", "archivo", "mapa", "manifiesto", "contenido"})
    void rechazaRegistroInconsistente(String problema) throws Exception {
        switch (problema) {
            case "duplicado" -> ((ArrayNode) registro.path("casos")).add(caso.deepCopy());
            case "cwe" -> caso.put("cweNormalizado", "CWE-89");
            case "clasificacion" -> caso.put("clasificacionEsperada", "INVENTADO");
            case "linea" -> caso.putArray("lineasOperacionVulnerablePreparadas").add(999);
            case "huella" -> caso.put("sha256PaqueteAnalisis", "0".repeat(64));
            case "archivo" -> caso.put("paqueteAnalisis", "../inexistente.zip");
            case "mapa" -> caso.putArray("correspondenciaLineas");
            case "manifiesto" -> caso.putArray("anotacionesManifiesto");
            case "contenido" -> {
                try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(raiz.resolve("casos/Uno.zip")))) {
                    zip.putNextEntry(new ZipEntry("respuestas.json")); zip.write(fuente); zip.closeEntry();
                }
                caso.put("sha256PaqueteAnalisis", hash(Files.readAllBytes(raiz.resolve("casos/Uno.zip"))));
            }
            default -> throw new IllegalStateException();
        }
        CatalogoJulietJson lector = lector();
        assertThatThrownBy(lector::cargar).isInstanceOf(ExcepcionEvaluacion.class);
    }
    @Test
    void validaRegistroRealSinEjecutarCasosNiAnalizadores() {
        Assumptions.assumeTrue(Files.exists(Path.of("configuracion-experimental/casos-prueba.json")));
        var catalogo = new CatalogoJulietJson(Path.of("."), Path.of("configuracion-experimental/casos-prueba.json"), MAPPER).cargar();
        assertThat(catalogo.casos()).isNotEmpty();
        assertThat(catalogo.casos()).allSatisfy(c -> assertThat(c.archivosPermitidos()).doesNotContainKey("casos-prueba.json"));
    }
    private String hash(byte[] datos) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(datos)); }
}
