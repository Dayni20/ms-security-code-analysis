package com.mssecuritycodeanalysis.application.port.out;

import java.util.List;

import com.mssecuritycodeanalysis.domain.model.ArchivoFuente;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisEstatico;

public interface AnalizadorEstatico {

    ResultadoAnalisisEstatico analizar(List<ArchivoFuente> archivos);
}
