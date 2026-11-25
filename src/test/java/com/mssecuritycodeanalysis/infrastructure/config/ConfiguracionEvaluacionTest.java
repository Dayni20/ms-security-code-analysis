package com.mssecuritycodeanalysis.infrastructure.config;

import static org.assertj.core.api.Assertions.*;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ConfiguracionEvaluacionTest {
    @TempDir Path temporal;
    private final ConfiguracionEvaluacion configuracion = new ConfiguracionEvaluacion();
    @Test
    void encuentraRaizDesdeDirectoriosDeClasesYJar() throws Exception {
        Path proyecto = temporal.resolve("Trabajo de Titulaci\u00f3n/proyecto");
        Files.createDirectories(proyecto.resolve("configuracion-experimental"));
        Files.writeString(proyecto.resolve("build.gradle"), "");
        Files.writeString(proyecto.resolve("settings.gradle"), "");
        Path catalogo = Path.of("configuracion-experimental/casos-prueba.json");
        Files.writeString(proyecto.resolve(catalogo), "{}");
        for (String subdirectorio : new String[]{"bin/main", "build/classes/java/main", "build/libs"}) {
            Path inicio = Files.createDirectories(proyecto.resolve(subdirectorio));
            assertThat(configuracion.buscarRaiz(inicio, catalogo)).isEqualTo(proyecto);
        }
    }
    @Test
    void respetaRaizConfiguradaExplicitamente() {
        PropiedadesEvaluacion propiedades = new PropiedadesEvaluacion(temporal.toString(), "referencia.json",
                "resultados", "modelo");
        assertThat(configuracion.resolverRaiz(propiedades)).isEqualTo(temporal.toAbsolutePath().normalize());
    }
    @Test
    void localizaCatalogoRealDesdeConfiguracionDeLaAplicacion() {
        org.junit.jupiter.api.Assumptions.assumeTrue(Files.isRegularFile(Path.of("configuracion-experimental/casos-prueba.json")));
        PropiedadesEvaluacion propiedades = new PropiedadesEvaluacion(".",
                "configuracion-experimental/casos-prueba.json", "resultados-experimentales", "modelo");
        var catalogo = configuracion.catalogoCasosExperimentales(propiedades,
                new com.fasterxml.jackson.databind.ObjectMapper().findAndRegisterModules());
        assertThat(catalogo.cargar().casos()).isNotEmpty();
    }
}
