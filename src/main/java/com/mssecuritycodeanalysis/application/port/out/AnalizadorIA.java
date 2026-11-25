package com.mssecuritycodeanalysis.application.port.out;

import java.util.List;

import com.mssecuritycodeanalysis.domain.model.ArchivoFuente;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisIA;

public interface AnalizadorIA {

    ResultadoAnalisisIA analizar(List<ArchivoFuente> archivos);
}
