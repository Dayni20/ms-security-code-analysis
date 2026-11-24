package com.mssecuritycodeanalysis.domain.model;

import com.mssecuritycodeanalysis.domain.Constantes;
public record ArchivoFuente(String rutaRelativa, String contenido, String lenguaje) {

    public ArchivoFuente {
        if (rutaRelativa == null || rutaRelativa.isBlank()) {
            throw new IllegalArgumentException(Constantes.MENSAJE_RUTA_ARCHIVO_OBLIGATORIA);
        }

        if (contenido == null) {
            throw new IllegalArgumentException(Constantes.MENSAJE_CONTENIDO_NULO);
        }

        if (lenguaje == null || lenguaje.isBlank()) {
            throw new IllegalArgumentException(Constantes.MENSAJE_LENGUAJE_OBLIGATORIO);
        }
    }
}
