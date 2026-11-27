package com.mssecuritycodeanalysis.infrastructure.adapter.out.pdf;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.ArrayList;
import java.util.Locale;

import org.apache.pdfbox.pdmodel.PDDocument;

import com.mssecuritycodeanalysis.application.port.out.GeneradorInformePdf;
import com.mssecuritycodeanalysis.domain.Constantes;
import com.mssecuritycodeanalysis.domain.model.HallazgoHibrido;
import com.mssecuritycodeanalysis.domain.model.HallazgoHibrido.EstadoRevision;
import com.mssecuritycodeanalysis.domain.model.HallazgoSeguridad;
import com.mssecuritycodeanalysis.domain.model.InformeAnalisis;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisEstatico;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisHibrido;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisHibrido.ResultadoMetodo;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisIA;

public class GeneradorInformePdfBox implements GeneradorInformePdf {
    private static final DateTimeFormatter FECHA = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm 'UTC'XXX", Locale.ROOT)
            .withZone(ZoneId.of(Constantes.ZONA_INFORME_PDF));

    @Override
    public byte[] generar(InformeAnalisis informe) {
        try (PDDocument documento = new PDDocument(); ByteArrayOutputStream salida = new ByteArrayOutputStream();
                DocumentoPdf pdf = new DocumentoPdf(documento)) {
            documento.getDocumentInformation().setTitle("Informe de análisis de seguridad");
            documento.getDocumentInformation().setAuthor("ms-security-code-analysis");
            documento.getDocumentInformation().setSubject("Alertas de seguridad del código fuente");
            pdf.titulo("Informe de análisis de seguridad");
            pdf.dato("Proyecto", informe.nombreProyecto());
            pdf.dato("Método", nombreMetodo(informe));
            pdf.dato("Estado", legible(informe.estado()));
            pdf.dato("Fecha del informe", fecha(informe.fechaGeneracion()));
            datoSiExiste(pdf, "Motivo", informe.motivo());
            datoSiExiste(pdf, "Error", informe.error());
            pdf.parrafo("Las alertas requieren revisión; no son vulnerabilidades confirmadas.");
            if (informe.hibrido() != null) escribirHibrido(pdf, informe.hibrido());
            else escribirIndividual(pdf, informe);
            pdf.finalizar();
            documento.save(salida);
            return salida.toByteArray();
        } catch (IOException excepcion) {
            throw new IllegalStateException(Constantes.MENSAJE_ERROR_PDF, excepcion);
        }
    }

    private void escribirIndividual(DocumentoPdf pdf, InformeAnalisis informe) throws IOException {
        List<HallazgoSeguridad> alertas = informe.estatico() != null ? informe.estatico().hallazgos() : informe.ia().hallazgos();
        List<String> archivos = informe.estatico() != null ? informe.estatico().archivosAnalizados() : informe.ia().archivosAnalizados();
        pdf.seccion("Resumen");
        pdf.dato("Archivos analizados", archivos.size());
        pdf.dato("Alertas encontradas", alertas.size());
        pdf.dato("Tiempo de la solicitud", duracion(informe.tiempoSolicitudMilisegundos()));
        if (informe.estatico() != null) escribirEstatico(pdf, informe.estatico());
        else escribirIA(pdf, informe.ia());
        pdf.seccion("Alertas encontradas");
        tabla(pdf, alertas);
    }

    private void escribirHibrido(DocumentoPdf pdf, ResultadoAnalisisHibrido resultado) throws IOException {
        pdf.seccion("Resumen");
        pdf.dato("Archivos analizados", resultado.archivosAnalizados().size());
        pdf.dato("Alertas encontradas", resultado.hallazgos().size());
        pdf.dato("Respaldadas por evidencia", contar(resultado, EstadoRevision.RESPALDADO_POR_EVIDENCIA));
        pdf.dato("Pendientes de revisión", contar(resultado, EstadoRevision.PENDIENTE_REVISION));
        pdf.dato("Descartadas", contar(resultado, EstadoRevision.DESCARTADO_CON_JUSTIFICACION));
        pdf.dato("Tiempo total", duracion(resultado.tiempos().totalMilisegundos()));
        pdf.seccion("Herramientas");
        estadoMetodo(pdf, "Semgrep", resultado.estatico());
        if (resultado.estatico().resultado() != null) escribirEstatico(pdf, resultado.estatico().resultado());
        estadoMetodo(pdf, "Inteligencia artificial", resultado.ia());
        if (resultado.ia().resultado() != null) escribirIA(pdf, resultado.ia().resultado());
        pdf.seccion("Alertas encontradas");
        if (resultado.hallazgos().isEmpty()) sinAlertas(pdf);
        else {
            pdf.cabeceraTabla();
            for (int indice = 0; indice < resultado.hallazgos().size(); indice++) {
                HallazgoHibrido alerta = resultado.hallazgos().get(indice);
                pdf.fila(List.of(alerta.cwe(), (indice + 1) + ". " + legible(alerta.estadoRevision().name()) + "\n" + alerta.descripcion(),
                        alerta.rutaRelativa(), String.valueOf(alerta.linea()), legible(alerta.nivelRiesgo()),
                        legible(alerta.metodoDeteccion().name())), color(alerta.estadoRevision()), false);
            }
        }
        for (int indice = 0; indice < resultado.hallazgos().size(); indice++) {
            detalleAlerta(pdf, resultado.hallazgos().get(indice), indice + 1);
        }
    }

    private void detalleAlerta(DocumentoPdf pdf, HallazgoHibrido alerta, int numero) throws IOException {
        List<String> parrafos = new ArrayList<>();
        List<String> reglas = alerta.originales().stream().map(HallazgoSeguridad::identificadorRegla)
                .filter(java.util.Objects::nonNull).distinct().toList();
        String coincidencia = "Coincidencia entre herramientas: " + legible(alerta.estadoCorrelacion().name());
        if (!reglas.isEmpty()) coincidencia += ". Reglas: " + String.join(", ", reglas);
        parrafos.add(coincidencia);
        if (alerta.justificacion() != null && !alerta.justificacion().isBlank()) {
            parrafos.add("Justificación: " + alerta.justificacion());
        }
        for (HallazgoHibrido.Evidencia evidencia : alerta.evidencia()) {
            parrafos.add("Evidencia - " + legible(evidencia.tipo().name()) + " (líneas " + evidencia.lineaInicio() + "-"
                    + evidencia.lineaFin() + "): " + evidencia.descripcion());
        }
        pdf.bloque("Alerta " + numero + " - " + legible(alerta.estadoRevision().name()), parrafos);
    }

    private void estadoMetodo(DocumentoPdf pdf, String nombre, ResultadoMetodo<?> resultado) throws IOException {
        int archivos = resultado.cobertura().archivosAnalizados().size();
        pdf.dato(nombre, legible(resultado.estado()) + " - " + archivos + (archivos == 1 ? " archivo" : " archivos")
                + " - " + duracion(resultado.tiempoMilisegundos()));
        if (resultado.error() != null) datoSiExiste(pdf, "Error", resultado.error());
        else if (resultado.motivo() != null) pdf.dato("Motivo", legible(resultado.motivo()));
        if (!resultado.cobertura().lenguajesSinVerificar().isEmpty()) {
            pdf.dato("Lenguajes no verificados", String.join(", ", resultado.cobertura().lenguajesSinVerificar()));
        }
        if (!resultado.cobertura().archivosNoAnalizados().isEmpty()) {
            pdf.dato("Archivos sin análisis completo", String.join(", ", resultado.cobertura().archivosNoAnalizados()));
        }
    }

    private void escribirEstatico(DocumentoPdf pdf, ResultadoAnalisisEstatico resultado) throws IOException {
        datoSiExiste(pdf, "Versión de Semgrep", resultado.versionSemgrep());
        lenguajesSinAnalizar(pdf, resultado.lenguajesSinReglas());
    }

    private void escribirIA(DocumentoPdf pdf, ResultadoAnalisisIA resultado) throws IOException {
        datoSiExiste(pdf, "Modelo de IA", resultado.modelo());
        lenguajesSinAnalizar(pdf, resultado.lenguajesSinCobertura());
        for (ResultadoAnalisisIA.DetalleFragmento fragmento : resultado.fragmentos()) {
            if ("ANALIZADO".equals(fragmento.estado())) continue;
            pdf.dato("Fragmento sin análisis completo", fragmento.rutaRelativa() + " (líneas "
                    + fragmento.lineaInicio() + "-" + fragmento.lineaFin() + ")");
            pdf.dato("Estado del fragmento", legible(fragmento.estado()));
            datoSiExiste(pdf, "Motivo", fragmento.motivo());
            datoSiExiste(pdf, "Detalle", fragmento.descripcion());
        }
    }

    private void lenguajesSinAnalizar(DocumentoPdf pdf, List<String> lenguajes) throws IOException {
        if (!lenguajes.isEmpty()) pdf.dato("Lenguajes que no se pueden analizar", String.join(", ", lenguajes));
    }

    private void tabla(DocumentoPdf pdf, List<HallazgoSeguridad> alertas) throws IOException {
        if (alertas.isEmpty()) {
            sinAlertas(pdf);
            return;
        }
        pdf.cabeceraTabla();
        for (int indice = 0; indice < alertas.size(); indice++) {
            HallazgoSeguridad alerta = alertas.get(indice);
            pdf.fila(List.of(unir(alerta.cwe()), alerta.descripcion(), alerta.rutaRelativa(), String.valueOf(alerta.linea()),
                    legible(alerta.nivelRiesgo()), legible(alerta.metodoDeteccion())),
                    indice % 2 == 0 ? new Color(241, 245, 248) : Color.WHITE, false);
        }
    }

    private void sinAlertas(DocumentoPdf pdf) throws IOException {
        pdf.parrafo("No se reportaron alertas. Esto no garantiza que el código sea seguro; revisa el estado del análisis.");
    }

    private long contar(ResultadoAnalisisHibrido resultado, EstadoRevision estado) {
        return resultado.hallazgos().stream().filter(alerta -> alerta.estadoRevision() == estado).count();
    }

    private Color color(EstadoRevision estado) {
        return switch (estado) {
            case RESPALDADO_POR_EVIDENCIA -> new Color(225, 242, 235);
            case PENDIENTE_REVISION -> new Color(255, 246, 222);
            case DESCARTADO_CON_JUSTIFICACION -> new Color(234, 236, 240);
        };
    }

    private void datoSiExiste(DocumentoPdf pdf, String etiqueta, String valor) throws IOException {
        if (valor != null && !valor.isBlank()) pdf.dato(etiqueta, valor);
    }

    private String fecha(Instant instante) {
        return instante == null ? Constantes.SIN_DATO_INFORME : FECHA.format(instante);
    }

    private String duracion(Long milisegundos) {
        if (milisegundos == null) return Constantes.SIN_DATO_INFORME;
        if (milisegundos < 60_000) return String.format(Locale.forLanguageTag("es"), "%.2f s", milisegundos / 1000.0);
        return String.format(Locale.ROOT, "%d min %02d s", milisegundos / 60_000, milisegundos / 1000 % 60);
    }

    private String unir(List<String> valores) {
        return valores.isEmpty() ? "No disponible" : String.join(", ", valores);
    }

    private String legible(String valor) {
        if (valor == null) return Constantes.SIN_DATO_INFORME;
        return switch (valor) {
            case "ESTATICO" -> "Semgrep";
            case "IA" -> "IA";
            case "AMBOS" -> "Semgrep e IA";
            case "CRITICO" -> "Crítico";
            case "RESPALDADO_POR_EVIDENCIA" -> "Respaldada por evidencia";
            case "DESCARTADO_CON_JUSTIFICACION" -> "Descartada con justificación";
            case "PENDIENTE_REVISION" -> "Pendiente de revisión";
            case "MISMA_OPERACION" -> "Misma operación identificada";
            case "SOLO_ESTATICO" -> "Solo Semgrep";
            case "SOLO_IA" -> "Solo IA";
            case "AMBIGUA" -> "Coincidencia ambigua";
            case "NO_COMPARABLE" -> "No se pudieron comparar";
            default -> valor.replace('_', ' ').toLowerCase(Locale.forLanguageTag("es"));
        };
    }

    private String nombreMetodo(InformeAnalisis informe) {
        return switch (informe.metodo()) {
            case ESTATICO -> "Estático - Semgrep";
            case IA -> "Inteligencia artificial - Qwen / Ollama";
            case HIBRIDO -> "Híbrido - Semgrep + IA";
        };
    }
}
