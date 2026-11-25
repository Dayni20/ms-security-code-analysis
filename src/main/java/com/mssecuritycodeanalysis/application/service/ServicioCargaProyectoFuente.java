package com.mssecuritycodeanalysis.application.service;

import java.io.InputStream;
import java.util.List;
import java.util.Locale;

import com.mssecuritycodeanalysis.application.port.out.LectorProyectoFuente;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionProyectoInvalido;
import com.mssecuritycodeanalysis.domain.Constantes;
import com.mssecuritycodeanalysis.domain.model.ArchivoFuente;

public class ServicioCargaProyectoFuente {

    private final LectorProyectoFuente lector;

    public ServicioCargaProyectoFuente(LectorProyectoFuente lector) {
        this.lector = lector;
    }

    public List<ArchivoFuente> cargar(String nombreArchivo, InputStream entrada) {
        validarNombreArchivo(nombreArchivo);
        validarEntrada(entrada);
        List<ArchivoFuente> archivos = List.copyOf(lector.leer(entrada));
        if (archivos.isEmpty()) {
            throw new ExcepcionProyectoInvalido(Constantes.MENSAJE_ZIP_SIN_ARCHIVOS_ADMITIDOS);
        }
        return archivos;
    }

    private void validarNombreArchivo(String nombreArchivo) {
        if (!tieneExtensionZip(nombreArchivo) || contieneRutaOCaracteresDeControl(nombreArchivo)) {
            throw new ExcepcionProyectoInvalido(Constantes.MENSAJE_NOMBRE_ZIP_INVALIDO);
        }
    }

    private boolean tieneExtensionZip(String nombreArchivo) {
        return nombreArchivo != null && !nombreArchivo.isBlank()
                && nombreArchivo.toLowerCase(Locale.ROOT).endsWith(Constantes.EXTENSION_ZIP);
    }

    private boolean contieneRutaOCaracteresDeControl(String nombreArchivo) {
        return nombreArchivo.contains(Constantes.SEPARADOR_RUTA_UNIX)
                || nombreArchivo.contains(Constantes.SEPARADOR_RUTA_WINDOWS)
                || nombreArchivo.contains(Constantes.SEPARADOR_UNIDAD)
                || nombreArchivo.chars().anyMatch(Character::isISOControl);
    }

    private void validarEntrada(InputStream entrada) {
        if (entrada == null) {
            throw new ExcepcionProyectoInvalido(Constantes.MENSAJE_ARCHIVO_OBLIGATORIO);
        }
    }
}
