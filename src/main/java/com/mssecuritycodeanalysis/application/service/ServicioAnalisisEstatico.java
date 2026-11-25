package com.mssecuritycodeanalysis.application.service;

import java.io.InputStream;
import java.util.List;

import com.mssecuritycodeanalysis.application.port.out.AnalizadorEstatico;
import com.mssecuritycodeanalysis.domain.model.ArchivoFuente;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisEstatico;

public class ServicioAnalisisEstatico {

    private final ServicioCargaProyectoFuente servicioCarga;
    private final AnalizadorEstatico analizador;

    public ServicioAnalisisEstatico(ServicioCargaProyectoFuente servicioCarga, AnalizadorEstatico analizador) {
        this.servicioCarga = servicioCarga;
        this.analizador = analizador;
    }

    public ResultadoAnalisisEstatico analizar(String nombreArchivo, InputStream entrada) {
        List<ArchivoFuente> archivos = servicioCarga.cargar(nombreArchivo, entrada);
        return analizador.analizar(archivos);
    }
}
