package com.mssecuritycodeanalysis.infrastructure.adapter.out.ollama;

public record FragmentoCodigo(String rutaRelativa, String lenguaje, int lineaInicio,
        int lineaFin, String codigoNumerado) {
}
