package com.mssecuritycodeanalysis.application.port.out;

import java.io.InputStream;
import java.util.List;

import com.mssecuritycodeanalysis.domain.model.ArchivoFuente;

public interface LectorProyectoFuente {

    List<ArchivoFuente> leer(InputStream entrada);
}
