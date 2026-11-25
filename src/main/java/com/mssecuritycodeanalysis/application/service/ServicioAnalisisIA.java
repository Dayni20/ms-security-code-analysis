package com.mssecuritycodeanalysis.application.service;

import java.io.InputStream;
import java.util.List;

import com.mssecuritycodeanalysis.application.port.out.AnalizadorIA;
import com.mssecuritycodeanalysis.domain.model.ArchivoFuente;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisIA;

public class ServicioAnalisisIA {

    private final ServicioCargaProyectoFuente servicioCarga;
    private final AnalizadorIA analizador;

    public ServicioAnalisisIA(ServicioCargaProyectoFuente servicioCarga, AnalizadorIA analizador) {
        this.servicioCarga = servicioCarga;
        this.analizador = analizador;
    }

    public ResultadoAnalisisIA analizar(String nombreArchivo, InputStream entrada) {
        List<ArchivoFuente> archivos = servicioCarga.cargar(nombreArchivo, entrada);
        return analizador.analizar(archivos);
    }
}
