package com.mssecuritycodeanalysis.infrastructure.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.mssecuritycodeanalysis.application.port.out.LectorProyectoFuente;
import com.mssecuritycodeanalysis.application.service.ServicioCargaProyectoFuente;
import com.mssecuritycodeanalysis.infrastructure.adapter.out.zip.LectorProyectoZip;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(PropiedadesCargaZip.class)
public class ConfiguracionCargaProyecto {

    @Bean
    LectorProyectoFuente lectorProyectoFuente(PropiedadesCargaZip propiedades) {
        return new LectorProyectoZip(propiedades);
    }

    @Bean
    ServicioCargaProyectoFuente servicioCargaProyectoFuente(LectorProyectoFuente lector) {
        return new ServicioCargaProyectoFuente(lector);
    }
}
