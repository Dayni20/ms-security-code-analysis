package com.mssecuritycodeanalysis.infrastructure.config;

import java.io.IOException;
import java.net.http.HttpClient;
import java.time.Duration;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mssecuritycodeanalysis.application.port.out.AnalizadorIA;
import com.mssecuritycodeanalysis.application.service.ServicioAnalisisIA;
import com.mssecuritycodeanalysis.application.service.ServicioCargaProyectoFuente;
import com.mssecuritycodeanalysis.infrastructure.adapter.out.ollama.AnalizadorOllama;
import com.mssecuritycodeanalysis.infrastructure.adapter.out.ollama.ClienteOllama;
import com.mssecuritycodeanalysis.infrastructure.adapter.out.ollama.ConstructorPromptIA;
import com.mssecuritycodeanalysis.infrastructure.adapter.out.ollama.FragmentadorCodigo;
import com.mssecuritycodeanalysis.infrastructure.adapter.out.ollama.InterpreteRespuestaIA;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(PropiedadesOllama.class)
public class ConfiguracionAnalisisIA {

    @Bean
    AnalizadorIA analizadorIA(PropiedadesOllama propiedades, ObjectMapper mapper,
            RestClient.Builder constructorCliente) throws IOException {
        HttpClient transporte = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(propiedades.timeoutConexionSegundos()))
                .followRedirects(HttpClient.Redirect.NEVER).build();
        JdkClientHttpRequestFactory solicitudes = new JdkClientHttpRequestFactory(transporte);
        solicitudes.setReadTimeout(Duration.ofSeconds(propiedades.timeoutRespuestaSegundos()));
        RestClient restClient = constructorCliente.baseUrl(propiedades.url().toString())
                .requestFactory(solicitudes).build();
        ClienteOllama cliente = new ClienteOllama(restClient, propiedades, mapper);
        ConstructorPromptIA prompt = new ConstructorPromptIA(mapper, propiedades);
        FragmentadorCodigo fragmentador = new FragmentadorCodigo(propiedades, prompt);
        return new AnalizadorOllama(propiedades, cliente, prompt, fragmentador, new InterpreteRespuestaIA(mapper));
    }

    @Bean
    ServicioAnalisisIA servicioAnalisisIA(ServicioCargaProyectoFuente servicioCarga, AnalizadorIA analizador) {
        return new ServicioAnalisisIA(servicioCarga, analizador);
    }
}
