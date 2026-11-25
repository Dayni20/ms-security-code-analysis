package com.mssecuritycodeanalysis.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mssecuritycodeanalysis.application.port.out.GeneradorInformePdf;
import com.mssecuritycodeanalysis.application.service.ServicioInformePdf;
import com.mssecuritycodeanalysis.infrastructure.adapter.in.rest.LectorSolicitudInforme;
import com.mssecuritycodeanalysis.infrastructure.adapter.out.pdf.GeneradorInformePdfBox;

@Configuration(proxyBeanMethods = false)
public class ConfiguracionInformePdf {
    @Bean
    GeneradorInformePdf generadorInformePdf() {
        return new GeneradorInformePdfBox();
    }

    @Bean
    ServicioInformePdf servicioInformePdf(GeneradorInformePdf generador) {
        return new ServicioInformePdf(generador);
    }

    @Bean
    LectorSolicitudInforme lectorSolicitudInforme(ObjectMapper mapper) {
        return new LectorSolicitudInforme(mapper);
    }
}
