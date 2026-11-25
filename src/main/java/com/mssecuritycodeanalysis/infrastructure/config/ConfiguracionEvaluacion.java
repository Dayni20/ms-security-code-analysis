package com.mssecuritycodeanalysis.infrastructure.config;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Files;
import org.springframework.boot.system.ApplicationHome;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mssecuritycodeanalysis.application.port.out.*;
import com.mssecuritycodeanalysis.application.service.*;
import com.mssecuritycodeanalysis.infrastructure.adapter.out.evaluacion.*;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(PropiedadesEvaluacion.class)
public class ConfiguracionEvaluacion {
    @Bean
    CatalogoCasosExperimentales catalogoCasosExperimentales(PropiedadesEvaluacion propiedades, ObjectMapper mapper) {
        return new CatalogoJulietJson(resolverRaiz(propiedades), Path.of(propiedades.catalogo()), mapper);
    }
    @Bean
    RepositorioEvaluaciones repositorioEvaluaciones(PropiedadesEvaluacion propiedades, ObjectMapper mapper) {
        return new RepositorioEvaluacionesJson(resolverRaiz(propiedades).resolve(propiedades.directorioResultados()), mapper);
    }
    Path resolverRaiz(PropiedadesEvaluacion propiedades) {
        Path configurada = Path.of(propiedades.raizProyecto());
        if (configurada.isAbsolute() || !configurada.normalize().toString().isEmpty()) {
            return configurada.toAbsolutePath().normalize();
        }
        Path directorioTrabajo = Path.of("").toAbsolutePath().normalize();
        Path encontrada = buscarRaiz(directorioTrabajo, Path.of(propiedades.catalogo()));
        if (encontrada != null) return encontrada;
        Path directorioAplicacion = new ApplicationHome(ConfiguracionEvaluacion.class).getDir().toPath();
        encontrada = buscarRaiz(directorioAplicacion, Path.of(propiedades.catalogo()));
        return encontrada == null ? directorioTrabajo : encontrada;
    }

    Path buscarRaiz(Path inicio, Path catalogo) {
        for (Path candidata = inicio.toAbsolutePath().normalize(); candidata != null; candidata = candidata.getParent()) {
            if (Files.isRegularFile(candidata.resolve("build.gradle"))
                    && Files.isRegularFile(candidata.resolve("settings.gradle"))
                    && Files.isRegularFile(candidata.resolve(catalogo))) return candidata;
        }
        return null;
    }

    @Bean(destroyMethod = "shutdownNow")
    ExecutorService ejecutorEvaluacion() {
        return Executors.newSingleThreadExecutor(tarea -> new Thread(tarea, "evaluacion-experimental"));
    }
    @Bean
    ServicioEvaluacionExperimental servicioEvaluacionExperimental(CatalogoCasosExperimentales catalogo,
            RepositorioEvaluaciones repositorio, ServicioCargaProyectoFuente carga, AnalizadorEstatico estatico,
            @Qualifier("ejecutorEvaluacion") ExecutorService ejecutor, PropiedadesEvaluacion evaluacion,
            PropiedadesOllama ollama, PropiedadesSemgrep semgrep, PropiedadesCargaZip cargaZip,
            ObjectMapper mapper, RestClient.Builder cliente) throws IOException {
        PropiedadesOllama experimental = new PropiedadesOllama(ollama.url(), evaluacion.modelo(), ollama.temperatura(),
                ollama.contexto(), ollama.maxTokensGeneracion(), ollama.semilla(), ollama.maxLineasFragmento(),
                ollama.maxCaracteresFragmento(), ollama.lineasSolapamiento(), ollama.margenTokens(),
                ollama.maxFragmentosPorArchivo(), ollama.timeoutConexionSegundos(), ollama.timeoutRespuestaSegundos(),
                ollama.maxBytesRespuesta(), ollama.lenguajesAdmitidos(), ollama.mantenerModeloSegundos());
        AnalizadorIA ia = ConfiguracionAnalisisIA.crearAnalizador(experimental, mapper, cliente.clone());
        ServicioAnalisisHibrido hibrido = new ServicioAnalisisHibrido(carga, estatico, ia);
        Map<String, String> parametros = new TreeMap<>();
        parametros.put("ollama", mapper.writeValueAsString(experimental));
        parametros.put("semgrep", mapper.writeValueAsString(semgrep));
        parametros.put("cargaZip", mapper.writeValueAsString(cargaZip));
        parametros.put("java", System.getProperty("java.version"));
        parametros.put("sistemaOperativo", System.getProperty("os.name") + " " + System.getProperty("os.arch"));
        parametros.put("versionesEfectivas", "Version Semgrep, hash de reglas, digest del modelo, parametros y prompt: en resultadosOriginales de cada caso; null significa no disponible");
        return new ServicioEvaluacionExperimental(catalogo, repositorio, hibrido, ejecutor, parametros);
    }
}
