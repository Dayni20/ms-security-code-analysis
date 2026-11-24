package com.mssecuritycodeanalysis.infrastructure.adapter.in.rest;

import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.mssecuritycodeanalysis.domain.Constantes;

@RestController
public class HealthController {

    private final String serviceName;

    public HealthController(@Value(Constantes.PROPIEDAD_NOMBRE_APLICACION) String serviceName) {
        this.serviceName = serviceName;
    }

    @GetMapping(Constantes.RUTA_ESTADO_SERVICIO)
    public Map<String, String> health() {
        return Map.of(Constantes.CLAVE_ESTADO, Constantes.ESTADO_SERVICIO_ACTIVO,
                Constantes.CLAVE_SERVICIO, serviceName);
    }
}
