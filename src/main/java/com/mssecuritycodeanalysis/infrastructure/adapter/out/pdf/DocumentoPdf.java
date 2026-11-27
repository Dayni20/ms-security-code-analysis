package com.mssecuritycodeanalysis.infrastructure.adapter.out.pdf;

import java.awt.Color;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType0Font;

import com.mssecuritycodeanalysis.domain.Constantes;

final class DocumentoPdf implements AutoCloseable {
    private static final float MARGEN = 44;
    private static final float ANCHO = PDRectangle.A4.getHeight();
    private static final float ALTO = PDRectangle.A4.getWidth();
    private static final float UTIL = ANCHO - MARGEN * 2;
    private static final Color TINTA = new Color(25, 42, 61);
    private static final Color ACENTO = new Color(17, 111, 101);
    private static final float[] COLUMNAS = {51, 226, 218, 35, 80, UTIL - 610};
    private static final List<String> CABECERAS = List.of("CWE", "Descripción de la alerta", "Archivo", "Línea", "Riesgo", "Detección");
    private final PDDocument documento;
    private final PDType0Font fuente;
    private PDPageContentStream contenido;
    private float y;
    private boolean unicodeRepresentado;

    DocumentoPdf(PDDocument documento) throws IOException {
        this.documento = documento;
        try (InputStream entrada = PDDocument.class.getResourceAsStream(Constantes.FUENTE_INFORME_PDF)) {
            if (entrada == null) throw new IOException(Constantes.MENSAJE_ERROR_PDF);
            fuente = PDType0Font.load(documento, entrada);
        }
        nuevaPagina();
    }

    private void nuevaPagina() throws IOException {
        if (contenido != null) contenido.close();
        if (documento.getNumberOfPages() >= 250) throw new IllegalArgumentException("El informe supera el límite de 250 páginas; reduce la cantidad de datos enviados");
        PDPage pagina = new PDPage(new PDRectangle(ANCHO, ALTO));
        documento.addPage(pagina);
        contenido = new PDPageContentStream(documento, pagina);
        rectangulo(MARGEN, ALTO - 43, UTIL, 4, ACENTO);
        dibujar("ANÁLISIS DE SEGURIDAD", MARGEN, ALTO - 64, 11, TINTA);
        dibujar("INFORME DE RESULTADOS", ANCHO - 295, ALTO - 64, 9, ACENTO);
        y = ALTO - 94;
    }

    void titulo(String texto) throws IOException {
        espacio(60);
        parrafo(texto, 23, TINTA);
        y -= 5;
    }

    void seccion(String titulo) throws IOException {
        espacio(70);
        y -= 12;
        parrafo(titulo, 13, ACENTO);
        y -= 4;
    }

    void bloque(String titulo, List<String> parrafos) throws IOException {
        float alto = 20 + envolver(titulo, UTIL, 13).size() * 17;
        for (String parrafo : parrafos) alto += envolver(parrafo, UTIL, 10).size() * 14 + 4;
        if (alto <= ALTO - 140) espacio(alto);
        seccion(titulo);
        for (String parrafo : parrafos) parrafo(parrafo);
    }

    void parrafo(String texto) throws IOException {
        parrafo(texto, 10, TINTA);
    }

    void dato(String etiqueta, Object valor) throws IOException {
        parrafo(etiqueta + ": " + (valor == null ? Constantes.SIN_DATO_INFORME : valor));
    }

    private void parrafo(String texto, float tamano, Color color) throws IOException {
        List<String> lineas = envolver(texto, UTIL, tamano);
        float alto = lineas.size() * (tamano + 4) + 4;
        if (alto < ALTO - 140) espacio(alto);
        for (String linea : lineas) {
            espacio(tamano + 9);
            dibujar(linea, MARGEN, y, tamano, color);
            y -= tamano + 4;
        }
        y -= 4;
    }

    private void espacio(float alto) throws IOException {
        if (y - alto < 43) nuevaPagina();
    }

    void cabeceraTabla() throws IOException {
        espacio(60);
        fila(CABECERAS, TINTA, true);
    }

    void fila(List<String> celdas, Color fondo, boolean cabecera) throws IOException {
        List<List<String>> lineas = new ArrayList<>();
        for (int indice = 0; indice < COLUMNAS.length; indice++) lineas.add(envolver(celdas.get(indice), COLUMNAS[indice] - 12, 9));
        int cantidad = lineas.stream().mapToInt(List::size).max().orElse(1);
        int desplazamiento = 0;
        while (desplazamiento < cantidad) {
            int capacidad = (int) ((y - 45 - 12) / 12);
            if (capacidad < 2) {
                nuevaPagina();
                if (!cabecera) cabeceraTabla();
                capacidad = (int) ((y - 45 - 12) / 12);
            }
            int tramo = Math.min(cantidad - desplazamiento, capacidad);
            float alto = tramo * 12 + 12;
            float x = MARGEN;
            for (int columna = 0; columna < COLUMNAS.length; columna++) {
                rectangulo(x, y - alto, COLUMNAS[columna], alto, fondo);
                List<String> celda = lineas.get(columna);
                int inicio = desplazamiento;
                if (inicio >= celda.size() && columna != 1 && columna != 2) inicio = 0;
                for (int linea = 0; linea < tramo && inicio + linea < celda.size(); linea++) {
                    dibujar(celda.get(inicio + linea), x + 6, y - 13 - linea * 12, 9, cabecera ? Color.WHITE : TINTA);
                }
                x += COLUMNAS[columna];
            }
            y -= alto;
            desplazamiento += tramo;
        }
    }

    private List<String> envolver(String original, float ancho, float tamano) throws IOException {
        String texto = representable(original == null ? Constantes.SIN_DATO_INFORME : original);
        List<String> lineas = new ArrayList<>();
        StringBuilder linea = new StringBuilder();
        float longitud = 0;
        for (int posicion = 0; posicion < texto.length();) {
            int codigo = texto.codePointAt(posicion);
            String caracter = new String(Character.toChars(codigo));
            posicion += Character.charCount(codigo);
            if (codigo == '\r') continue;
            float medida = codigo == '\n' ? 0 : fuente.getStringWidth(caracter) * tamano / 1000;
            if (codigo != '\n' && longitud + medida > ancho && linea.lastIndexOf(" ") > 0) {
                int espacio = linea.lastIndexOf(" ");
                lineas.add(linea.substring(0, espacio));
                linea.delete(0, espacio + 1);
                longitud = fuente.getStringWidth(linea.toString()) * tamano / 1000;
            } else if (codigo == '\n' || longitud + medida > ancho) {
                lineas.add(linea.toString());
                linea.setLength(0);
                longitud = 0;
            }
            if (codigo != '\n') {
                if (longitud + medida > ancho && !linea.isEmpty()) {
                    lineas.add(linea.toString());
                    linea.setLength(0);
                    longitud = 0;
                }
                linea.append(caracter);
                longitud += medida;
            }
        }
        lineas.add(linea.toString());
        return lineas;
    }

    private String representable(String texto) throws IOException {
        StringBuilder salida = new StringBuilder();
        for (int indice = 0; indice < texto.length();) {
            int codigo = texto.codePointAt(indice);
            indice += Character.charCount(codigo);
            if (codigo == '\n' || codigo == '\r') salida.appendCodePoint(codigo);
            else if (codigo == '\t') salida.append(' ');
            else {
                String caracter = new String(Character.toChars(codigo));
                try {
                    fuente.encode(caracter);
                    salida.append(caracter);
                } catch (IllegalArgumentException excepcion) {
                    unicodeRepresentado = true;
                    salida.append("[U+").append(Integer.toHexString(codigo).toUpperCase(java.util.Locale.ROOT)).append(']');
                }
            }
        }
        return salida.toString();
    }

    private void dibujar(String texto, float x, float posicion, float tamano, Color color) throws IOException {
        contenido.beginText();
        contenido.setFont(fuente, tamano);
        contenido.setNonStrokingColor(color);
        contenido.newLineAtOffset(x, posicion);
        contenido.showText(texto);
        contenido.endText();
    }

    private void rectangulo(float x, float posicion, float ancho, float alto, Color color) throws IOException {
        contenido.setNonStrokingColor(color);
        contenido.addRect(x, posicion, ancho, alto);
        contenido.fill();
    }

    void finalizar() throws IOException {
        if (unicodeRepresentado) {
            seccion("Representación de caracteres");
            parrafo("Los caracteres sin glifo disponible en la fuente se representan mediante su código Unicode [U+XXXX], sin ocultarlos ni sustituirlos por símbolos ambiguos.");
        }
        contenido.close();
        contenido = null;
        int total = documento.getNumberOfPages();
        for (int indice = 0; indice < total; indice++) {
            try (PDPageContentStream pie = new PDPageContentStream(documento, documento.getPage(indice), PDPageContentStream.AppendMode.APPEND, true, true)) {
                pie.beginText();
                pie.setFont(fuente, 8);
                pie.setNonStrokingColor(TINTA);
                pie.newLineAtOffset(MARGEN, 24);
                pie.showText("Informe de seguridad");
                pie.newLineAtOffset(UTIL - 110, 0);
                pie.showText("Página " + (indice + 1) + " de " + total);
                pie.endText();
            }
        }
    }

    @Override
    public void close() throws IOException {
        if (contenido != null) contenido.close();
    }
}
