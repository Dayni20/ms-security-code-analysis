package com.mssecuritycodeanalysis.infrastructure.config;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.mssecuritycodeanalysis.application.service.ServicioAnalisisHibrido;
import com.mssecuritycodeanalysis.application.service.ServicioCargaProyectoFuente;
import com.mssecuritycodeanalysis.application.port.out.AnalizadorEstatico;
import com.mssecuritycodeanalysis.application.port.out.AnalizadorIA;
@Configuration(proxyBeanMethods = false)
public class ConfiguracionAnalisisHibrido {
    @Bean
    ServicioAnalisisHibrido servicioAnalisisHibrido(ServicioCargaProyectoFuente carga, AnalizadorEstatico estatico, AnalizadorIA ia) {
        return new ServicioAnalisisHibrido(carga, estatico, ia);
    }
}
