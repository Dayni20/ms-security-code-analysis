package com.mssecuritycodeanalysis.infrastructure.adapter.out.zip;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;

import com.mssecuritycodeanalysis.application.port.out.LectorProyectoFuente;
import com.mssecuritycodeanalysis.application.service.ExcepcionProyectoInvalido.Motivo;
import com.mssecuritycodeanalysis.application.service.ExcepcionProyectoInvalido;
import com.mssecuritycodeanalysis.domain.Constantes;
import com.mssecuritycodeanalysis.domain.model.ArchivoFuente;
import com.mssecuritycodeanalysis.infrastructure.config.PropiedadesCargaZip;

public class LectorProyectoZip implements LectorProyectoFuente {

    private static final int TAMANO_BLOQUE = 8192;

    private final PropiedadesCargaZip limites;

    public LectorProyectoZip(PropiedadesCargaZip limites) {
        this.limites = limites;
    }

    @Override
    public List<ArchivoFuente> leer(InputStream entrada) {
        try {
            Path archivoTemporal = crearArchivoTemporal();
            try {
                copiarZip(entrada, archivoTemporal);
                return leerZip(archivoTemporal);
            } finally {
                Files.deleteIfExists(archivoTemporal);
            }
        } catch (ZipException | EOFException excepcion) {
            throw new ExcepcionProyectoInvalido(Constantes.MENSAJE_ZIP_DANADO);
        } catch (IOException excepcion) {
            throw new UncheckedIOException(Constantes.MENSAJE_ERROR_PROCESAR_ARCHIVO, excepcion);
        }
    }

    private Path crearArchivoTemporal() throws IOException {
        Files.createDirectories(limites.directorioTemporal());
        return Files.createTempFile(limites.directorioTemporal(),
                Constantes.PREFIJO_ARCHIVO_TEMPORAL, Constantes.EXTENSION_ZIP);
    }

    private void copiarZip(InputStream entrada, Path archivoTemporal) throws IOException {
        long bytesCopiados = 0;
        byte[] bloque = new byte[TAMANO_BLOQUE];
        try (var salida = Files.newOutputStream(archivoTemporal)) {
            int bytesLeidos;
            while ((bytesLeidos = entrada.read(bloque)) != -1) {
                if (bytesLeidos > limites.maxBytesZip() - bytesCopiados) {
                    throw limiteExcedido(Constantes.MENSAJE_LIMITE_TAMANO_ZIP);
                }
                salida.write(bloque, 0, bytesLeidos);
                bytesCopiados += bytesLeidos;
            }
        }
        if (bytesCopiados == 0) {
            throw new ExcepcionProyectoInvalido(Constantes.MENSAJE_ARCHIVO_VACIO);
        }
    }

    private List<ArchivoFuente> leerZip(Path archivoTemporal) throws IOException {
        List<ArchivoFuente> archivos = new ArrayList<>();
        Set<String> rutas = new HashSet<>();
        long bytesDescomprimidos = 0;
        try (ZipFile zip = new ZipFile(archivoTemporal.toFile(), StandardCharsets.UTF_8)) {
            validarCantidadEntradas(zip.size());
            var entradas = zip.entries();
            while (entradas.hasMoreElements()) {
                ZipEntry entrada = entradas.nextElement();
                String ruta = validarRuta(entrada.getName());
                validarRutaUnica(ruta, rutas);
                validarLimitesDescompresion(entrada.getSize(), 0, bytesDescomprimidos);
                String lenguaje = entrada.isDirectory() ? null : identificarLenguaje(ruta);
                ByteArrayOutputStream contenido = lenguaje != null ? new ByteArrayOutputStream() : null;
                bytesDescomprimidos += leerContenidoEntrada(zip, entrada, contenido, bytesDescomprimidos);
                if (lenguaje != null) {
                    archivos.add(new ArchivoFuente(ruta, decodificarContenido(contenido.toByteArray()), lenguaje));
                }
            }
        }
        return List.copyOf(archivos);
    }

    private String identificarLenguaje(String ruta) {
        int inicioExtension = ruta.lastIndexOf(Constantes.CARACTER_PUNTO);
        if (inicioExtension < 0) {
            return null;
        }
        String extension = ruta.substring(inicioExtension + 1).toLowerCase(Locale.ROOT);
        return limites.lenguajesPorExtension().get(extension);
    }

    private long leerContenidoEntrada(ZipFile zip, ZipEntry entrada, ByteArrayOutputStream contenido,
            long bytesDescomprimidos) throws IOException {
        CRC32 verificadorCrc = new CRC32();
        long bytesEntrada = 0;
        byte[] bloque = new byte[TAMANO_BLOQUE];
        try (InputStream flujo = zip.getInputStream(entrada)) {
            int bytesLeidos;
            while ((bytesLeidos = flujo.read(bloque)) != -1) {
                validarLimitesDescompresion(bytesLeidos, bytesEntrada, bytesDescomprimidos + bytesEntrada);
                bytesEntrada += bytesLeidos;
                verificadorCrc.update(bloque, 0, bytesLeidos);
                if (contenido != null) {
                    contenido.write(bloque, 0, bytesLeidos);
                }
            }
        }
        validarIntegridadEntrada(entrada, bytesEntrada, verificadorCrc.getValue());
        return bytesEntrada;
    }

    private void validarCantidadEntradas(int cantidadEntradas) {
        if (cantidadEntradas > limites.maxEntradas()) {
            throw limiteExcedido(Constantes.MENSAJE_LIMITE_ENTRADAS);
        }
    }

    private void validarLimitesDescompresion(long bytesNuevos, long bytesEntrada, long bytesDescomprimidos) {
        boolean superaLimiteEntrada = bytesNuevos > limites.maxBytesEntrada() - bytesEntrada;
        boolean superaLimiteTotal = bytesNuevos > limites.maxBytesDescomprimidos() - bytesDescomprimidos;
        if (superaLimiteEntrada || superaLimiteTotal) {
            throw limiteExcedido(Constantes.MENSAJE_LIMITE_DESCOMPRESION);
        }
    }

    private void validarIntegridadEntrada(ZipEntry entrada, long bytesEntrada, long crcCalculado) {
        boolean tamanoIncorrecto = bytesEntrada != entrada.getSize();
        boolean crcIncorrecto = crcCalculado != entrada.getCrc();
        boolean directorioConContenido = entrada.isDirectory() && bytesEntrada != 0;
        if (tamanoIncorrecto || crcIncorrecto || directorioConContenido) {
            throw new ExcepcionProyectoInvalido(Constantes.MENSAJE_ENTRADA_ZIP_DANADA);
        }
    }

    private void validarRutaUnica(String ruta, Set<String> rutas) {
        String rutaUnica = ruta.endsWith(Constantes.SEPARADOR_RUTA_UNIX)
                ? ruta.substring(0, ruta.length() - 1) : ruta;
        if (!rutas.add(rutaUnica)) {
            throw new ExcepcionProyectoInvalido(Constantes.MENSAJE_RUTAS_DUPLICADAS);
        }
    }

    private String validarRuta(String nombre) {
        String ruta = nombre.replace(Constantes.CARACTER_SEPARADOR_WINDOWS, Constantes.CARACTER_SEPARADOR_UNIX);
        if (esRutaNoPermitida(ruta)) {
            throw new ExcepcionProyectoInvalido(Constantes.MENSAJE_RUTA_NO_PERMITIDA);
        }
        for (String segmento : ruta.split(Constantes.SEPARADOR_RUTA_UNIX)) {
            if (esSegmentoNoPermitido(segmento)) {
                throw new ExcepcionProyectoInvalido(Constantes.MENSAJE_RUTA_NO_PERMITIDA);
            }
        }
        return ruta;
    }

    private boolean esRutaNoPermitida(String ruta) {
        return ruta.isBlank() || ruta.startsWith(Constantes.SEPARADOR_RUTA_UNIX)
                || ruta.contains(Constantes.SEPARADOR_UNIDAD)
                || ruta.chars().anyMatch(Character::isISOControl);
    }

    private boolean esSegmentoNoPermitido(String segmento) {
        return segmento.isEmpty() || segmento.equals(Constantes.SEGMENTO_DIRECTORIO_PADRE)
                || segmento.equals(Constantes.SEGMENTO_DIRECTORIO_ACTUAL);
    }

    private String decodificarContenido(byte[] contenido) {
        try {
            return StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(contenido)).toString();
        } catch (CharacterCodingException excepcion) {
            throw new ExcepcionProyectoInvalido(Constantes.MENSAJE_CODIFICACION_INVALIDA);
        }
    }

    private ExcepcionProyectoInvalido limiteExcedido(String mensaje) {
        return new ExcepcionProyectoInvalido(mensaje, Motivo.LIMITE_EXCEDIDO);
    }
}
