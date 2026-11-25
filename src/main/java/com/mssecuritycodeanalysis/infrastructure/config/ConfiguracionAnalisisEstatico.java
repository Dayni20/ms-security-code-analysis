package com.mssecuritycodeanalysis.infrastructure.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mssecuritycodeanalysis.application.port.out.AnalizadorEstatico;
import com.mssecuritycodeanalysis.application.service.ServicioAnalisisEstatico;
import com.mssecuritycodeanalysis.application.service.ServicioCargaProyectoFuente;
import com.mssecuritycodeanalysis.infrastructure.adapter.out.semgrep.AnalizadorSemgrep;
import com.mssecuritycodeanalysis.infrastructure.adapter.out.semgrep.EjecutorSemgrep;
import com.mssecuritycodeanalysis.infrastructure.adapter.out.semgrep.InterpreteResultadoSemgrep;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(PropiedadesSemgrep.class)
public class ConfiguracionAnalisisEstatico {

    @Bean
    AnalizadorEstatico analizadorEstatico(PropiedadesSemgrep propiedades,
            PropiedadesCargaZip propiedadesCarga, ObjectMapper objectMapper) {
        EjecutorSemgrep ejecutor = new EjecutorSemgrep(propiedades, propiedadesCarga.maxBytesEntrada());
        InterpreteResultadoSemgrep interprete = new InterpreteResultadoSemgrep(objectMapper);
        return new AnalizadorSemgrep(propiedades, propiedadesCarga.directorioTemporal(), ejecutor, interprete);
    }

    @Bean
    ServicioAnalisisEstatico servicioAnalisisEstatico(ServicioCargaProyectoFuente servicioCarga,
            AnalizadorEstatico analizador) {
        return new ServicioAnalisisEstatico(servicioCarga, analizador);
    }
}
