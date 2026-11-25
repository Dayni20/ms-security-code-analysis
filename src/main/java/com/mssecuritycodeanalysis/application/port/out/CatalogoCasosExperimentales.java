package com.mssecuritycodeanalysis.application.port.out;

import java.io.InputStream;
import java.util.List;
import java.util.Map;
import com.mssecuritycodeanalysis.domain.model.evaluacion.CasoExperimental;

public interface CatalogoCasosExperimentales {
    Catalogo cargar();
    InputStream abrir(CasoExperimental caso);
    record Catalogo(List<CasoExperimental> casos, Map<String, String> integridad) {
        public Catalogo { casos = List.copyOf(casos); integridad = Map.copyOf(integridad); }
    }
}
