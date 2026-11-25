package com.mssecuritycodeanalysis.application.service;

import com.mssecuritycodeanalysis.application.port.out.GeneradorInformePdf;
import com.mssecuritycodeanalysis.domain.model.InformeAnalisis;

public class ServicioInformePdf {
    private final GeneradorInformePdf generador;

    public ServicioInformePdf(GeneradorInformePdf generador) {
        this.generador = generador;
    }

    public byte[] generar(InformeAnalisis informe) {
        return generador.generar(informe);
    }
}
