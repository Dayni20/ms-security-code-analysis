package com.mssecuritycodeanalysis.application.port.out;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import com.mssecuritycodeanalysis.domain.model.evaluacion.EvaluacionExperimental;

public interface RepositorioEvaluaciones {
    void crear(EvaluacionExperimental evaluacion);
    void guardar(EvaluacionExperimental evaluacion);
    Optional<EvaluacionExperimental> buscar(UUID identificador);
    List<EvaluacionExperimental> listar();
}
