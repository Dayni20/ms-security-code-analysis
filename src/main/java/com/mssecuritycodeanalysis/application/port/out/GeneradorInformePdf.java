package com.mssecuritycodeanalysis.application.port.out;

import com.mssecuritycodeanalysis.domain.model.InformeAnalisis;

public interface GeneradorInformePdf {
    byte[] generar(InformeAnalisis informe);
}
