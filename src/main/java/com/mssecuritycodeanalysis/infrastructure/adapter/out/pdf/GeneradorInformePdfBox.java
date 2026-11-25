package com.mssecuritycodeanalysis.infrastructure.adapter.out.pdf;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
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
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisHibrido.CoberturaAnalizador;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisHibrido.ResultadoMetodo;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisIA;

public class GeneradorInformePdfBox implements GeneradorInformePdf {
    private static final DateTimeFormatter FECHA = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss XXX", Locale.ROOT)
            .withZone(ZoneId.of(Constantes.ZONA_INFORME_PDF));

    @Override
    public byte[] generar(InformeAnalisis informe) {
        try (PDDocument documento = new PDDocument(); ByteArrayOutputStream salida = new ByteArrayOutputStream();
                DocumentoPdf pdf = new DocumentoPdf(documento)) {
            documento.getDocumentInformation().setTitle("Informe de análisis de seguridad del código fuente");
            documento.getDocumentInformation().setAuthor("ms-security-code-analysis");
            documento.getDocumentInformation().setSubject("Indicios de seguridad: CWE-89, CWE-78 y CWE-22");
            pdf.titulo("Informe de análisis de seguridad");
            pdf.dato("Proyecto analizado", informe.nombreProyecto());
            pdf.dato("Método", nombreMetodo(informe));
            pdf.dato("Estado declarado", legible(informe.estado()));
            if (informe.motivo() != null) pdf.dato("Motivo informado", informe.motivo());
            if (informe.error() != null) pdf.dato("Error informado", informe.error());
            pdf.dato("Generación del informe", fecha(informe.fechaGeneracion()));
            pdf.dato("Zona horaria", Constantes.ZONA_INFORME_PDF);
            pdf.dato("Fecha del análisis declarada por el cliente", fecha(informe.fechaAnalisisDeclarada()));
            pdf.parrafo(Constantes.AVISO_INFORME_PDF);
            pdf.parrafo(Constantes.ORIGEN_INFORME_PDF);
            if (informe.hibrido() != null) escribirHibrido(pdf, informe);
            else escribirIndividual(pdf, informe);
            pdf.seccion("Interpretación y alcance");
            pdf.parrafo(Constantes.AVISO_INFORME_PDF);
            pdf.parrafo("Un estado completado describe la ejecución, no la confirmación de las alertas. Los resultados parciales, la falta de cobertura y los errores deben considerarse antes de concluir sobre el proyecto.");
            pdf.finalizar();
            documento.save(salida);
            return salida.toByteArray();
        } catch (IOException excepcion) {
            throw new IllegalStateException(Constantes.MENSAJE_ERROR_PDF, excepcion);
        }
    }

    private void escribirIndividual(DocumentoPdf pdf, InformeAnalisis informe) throws IOException {
        List<HallazgoSeguridad> hallazgos = informe.estatico() != null ? informe.estatico().hallazgos() : informe.ia().hallazgos();
        List<String> archivos = informe.estatico() != null ? informe.estatico().archivosAnalizados() : informe.ia().archivosAnalizados();
        pdf.seccion("Resumen del resultado");
        pdf.dato("Archivos analizados", archivos.size());
        pdf.dato("Hallazgos reportados", hallazgos.size());
        pdf.dato("Tiempo de la solicitud declarado por el navegador (ms)", informe.tiempoSolicitudMilisegundos());
        pdf.parrafo("El endpoint individual no informa un tiempo total del servidor. El tiempo de solicitud, cuando se aporta, incluye comunicación y procesamiento; no es una medición experimental certificada.");
        pdf.seccion("Hallazgos reportados");
        tabla(pdf, hallazgos);
        if (informe.estatico() != null) escribirEstatico(pdf, informe.estatico());
        else escribirIA(pdf, informe.ia());
        pdf.seccion("Archivos analizados");
        textos(pdf, archivos);
    }

    private void escribirHibrido(DocumentoPdf pdf, InformeAnalisis informe) throws IOException {
        ResultadoAnalisisHibrido resultado = informe.hibrido();
        pdf.seccion("Resumen híbrido");
        pdf.dato("Archivos analizados por al menos un método", resultado.archivosAnalizados().size());
        pdf.dato("Hallazgos consolidados, incluidos los descartados", resultado.hallazgos().size());
        pdf.dato("Respaldados por evidencia local", contar(resultado, EstadoRevision.RESPALDADO_POR_EVIDENCIA));
        pdf.dato("Pendientes de revisión", contar(resultado, EstadoRevision.PENDIENTE_REVISION));
        pdf.dato("Descartados con justificación", contar(resultado, EstadoRevision.DESCARTADO_CON_JUSTIFICACION));
        pdf.dato("Tiempo total informado por el servidor (ms)", resultado.tiempos().totalMilisegundos());
        pdf.dato("Carga / Semgrep / IA / correlación (ms)", resultado.tiempos().cargaMilisegundos() + " / "
                + resultado.tiempos().estaticoMilisegundos() + " / " + resultado.tiempos().iaMilisegundos() + " / "
                + resultado.tiempos().correlacionMilisegundos());
        pdf.dato("Ejecución concurrente", resultado.tiempos().concurrente() ? "Sí" : "No");
        pdf.parrafo("Respaldado significa evidencia local disponible, no vulnerabilidad confirmada. Los descartados se mantienen en el informe y pueden consultarse junto con sus detecciones originales.");
        pdf.seccion("Tabla de hallazgos híbridos");
        if (resultado.hallazgos().isEmpty()) sinHallazgos(pdf);
        else {
            pdf.cabeceraTabla();
            for (HallazgoHibrido hallazgo : resultado.hallazgos()) pdf.fila(List.of(hallazgo.cwe(),
                    legible(hallazgo.estadoRevision().name()) + ": " + hallazgo.descripcion(), hallazgo.rutaRelativa(), String.valueOf(hallazgo.linea()),
                    legible(hallazgo.nivelRiesgo()), legible(hallazgo.metodoDeteccion().name())), color(hallazgo.estadoRevision()), false);
        }
        for (HallazgoHibrido hallazgo : resultado.hallazgos()) {
            pdf.seccion("Detalle " + hallazgo.identificador() + " - " + legible(hallazgo.estadoRevision().name()));
            pdf.dato("Archivo / línea / CWE", hallazgo.rutaRelativa() + " / " + hallazgo.linea() + " / " + hallazgo.cwe());
            pdf.dato("Procedencia", legible(hallazgo.metodoDeteccion().name()));
            pdf.dato("Correlación", legible(hallazgo.estadoCorrelacion().name()));
            pdf.dato("Revisión", legible(hallazgo.estadoRevision().name()));
            pdf.dato("Justificación", hallazgo.justificacion());
            pdf.dato("Evidencias registradas", hallazgo.evidencia().size());
            for (HallazgoHibrido.Evidencia evidencia : hallazgo.evidencia()) pdf.parrafo(legible(evidencia.tipo().name())
                    + " · líneas " + evidencia.lineaInicio() + "-" + evidencia.lineaFin() + ": " + evidencia.descripcion());
            pdf.dato("Detecciones originales conservadas", hallazgo.originales().size());
            for (HallazgoSeguridad original : hallazgo.originales()) {
                pdf.dato("Regla / método", original.identificadorRegla() + " / " + legible(original.metodoDeteccion()));
                pdf.dato("CWE / archivo / línea / riesgo", String.join(", ", original.cwe()) + " / " + original.rutaRelativa()
                        + " / " + original.linea() + " / " + legible(original.nivelRiesgo()));
                pdf.dato("Descripción original", original.descripcion());
            }
        }
        estadoMetodo(pdf, "Semgrep", resultado.estatico());
        if (resultado.estatico().resultado() != null) escribirEstatico(pdf, resultado.estatico().resultado());
        estadoMetodo(pdf, "Inteligencia artificial", resultado.ia());
        if (resultado.ia().resultado() != null) escribirIA(pdf, resultado.ia().resultado());
        pdf.seccion("Trazabilidad de correlación");
        pdf.dato("Versión", resultado.versionCorrelacion());
        textos(pdf, resultado.criterios());
        pdf.seccion("Limitaciones del método híbrido");
        textos(pdf, resultado.limitaciones());
        pdf.seccion("Archivos recibidos");
        textos(pdf, resultado.archivosRecibidos());
        pdf.seccion("Archivos analizados por al menos un método");
        textos(pdf, resultado.archivosAnalizados());
    }

    private void estadoMetodo(DocumentoPdf pdf, String nombre, ResultadoMetodo<?> resultado) throws IOException {
        pdf.seccion("Estado y cobertura: " + nombre);
        pdf.dato("Estado", legible(resultado.estado()));
        pdf.dato("Tiempo informado (ms)", resultado.tiempoMilisegundos());
        pdf.dato("Motivo", resultado.motivo());
        pdf.dato("Error", resultado.error());
        CoberturaAnalizador cobertura = resultado.cobertura();
        cobertura(pdf, cobertura.lenguajesReconocidos(), cobertura.lenguajesConCobertura(), cobertura.lenguajesSinCobertura());
        pdf.dato("Lenguajes sin verificar", unir(cobertura.lenguajesSinVerificar()));
        pdf.dato("Archivos analizados", unir(cobertura.archivosAnalizados()));
        pdf.dato("Archivos no analizados", unir(cobertura.archivosNoAnalizados()));
    }

    private void escribirEstatico(DocumentoPdf pdf, ResultadoAnalisisEstatico resultado) throws IOException {
        pdf.seccion("Semgrep: cobertura y reproducibilidad");
        pdf.dato("Versión Semgrep", resultado.versionSemgrep());
        pdf.dato("Huella SHA-256 de las reglas locales", resultado.huellaReglas());
        cobertura(pdf, resultado.lenguajesReconocidos(), resultado.lenguajesConReglas(), resultado.lenguajesSinReglas());
        pdf.dato("Archivos con análisis disponible", unir(resultado.archivosAnalizados()));
        pdf.parrafo("El resultado recibido no incluye otros parámetros de ejecución de Semgrep; no se infieren desde la configuración actual, que podría haber cambiado.");
        pdf.parrafo("Las reglas estáticas tienen cobertura limitada. La ausencia de coincidencias no descarta flujos no contemplados, falsos negativos ni errores fuera de la cobertura declarada.");
    }

    private void escribirIA(DocumentoPdf pdf, ResultadoAnalisisIA resultado) throws IOException {
        pdf.seccion("IA: cobertura y reproducibilidad");
        pdf.dato("Estado de IA", legible(resultado.estado()));
        pdf.dato("Modelo", resultado.modelo());
        pdf.dato("Digest del modelo", resultado.digestModelo());
        pdf.dato("Método de detección", resultado.metodoDeteccion());
        pdf.dato("Versión del prompt", resultado.versionPrompt());
        pdf.dato("Huella SHA-256 del prompt", resultado.huellaPrompt());
        cobertura(pdf, resultado.lenguajesReconocidos(), resultado.lenguajesConCobertura(), resultado.lenguajesSinCobertura());
        ResultadoAnalisisIA.ParametrosGeneracion parametros = resultado.parametros();
        pdf.dato("Temperatura / semilla", parametros.temperatura() + " / " + parametros.semilla());
        pdf.dato("Contexto / máximo de tokens generados / margen de tokens", parametros.contexto() + " / "
                + parametros.maxTokensGeneracion() + " / " + parametros.margenTokens());
        pdf.dato("Máximo de líneas / caracteres por fragmento", parametros.maxLineasFragmento() + " / " + parametros.maxCaracteresFragmento());
        pdf.dato("Líneas de solapamiento / máximo de fragmentos por archivo", parametros.lineasSolapamiento() + " / " + parametros.maxFragmentosPorArchivo());
        pdf.dato("Archivos completamente analizados por IA", unir(resultado.archivosAnalizados()));
        pdf.seccion("Trazabilidad de fragmentos de IA");
        if (resultado.fragmentos().isEmpty()) pdf.parrafo("Sin fragmentos registrados en la respuesta recibida.");
        for (ResultadoAnalisisIA.DetalleFragmento fragmento : resultado.fragmentos()) {
            pdf.dato("Archivo / líneas / estado", fragmento.rutaRelativa() + " / " + fragmento.lineaInicio() + "-"
                    + fragmento.lineaFin() + " / " + legible(fragmento.estado()));
            pdf.dato("Motivo / descripción", texto(fragmento.motivo()) + " / " + texto(fragmento.descripcion()));
            pdf.dato("Huella de la solicitud", fragmento.huellaSolicitud());
        }
        pdf.seccion("Limitaciones de IA");
        textos(pdf, resultado.limitaciones());
    }

    private void cobertura(DocumentoPdf pdf, List<String> reconocidos, List<String> cubiertos, List<String> sinCobertura) throws IOException {
        pdf.dato("Lenguajes reconocidos", unir(reconocidos));
        pdf.dato("Lenguajes con cobertura declarada", unir(cubiertos));
        pdf.dato("Lenguajes sin cobertura", unir(sinCobertura));
        pdf.parrafo("La cobertura declarada y los archivos efectivamente analizados son datos distintos. Sin cobertura o con ejecución fallida no puede inferirse ausencia de vulnerabilidades.");
    }

    private void tabla(DocumentoPdf pdf, List<HallazgoSeguridad> hallazgos) throws IOException {
        if (hallazgos.isEmpty()) {
            sinHallazgos(pdf);
            return;
        }
        pdf.cabeceraTabla();
        for (int indice = 0; indice < hallazgos.size(); indice++) {
            HallazgoSeguridad hallazgo = hallazgos.get(indice);
            pdf.fila(List.of(unir(hallazgo.cwe()), hallazgo.descripcion(), hallazgo.rutaRelativa(), String.valueOf(hallazgo.linea()),
                    legible(hallazgo.nivelRiesgo()), legible(hallazgo.metodoDeteccion())),
                    indice % 2 == 0 ? new Color(241, 245, 248) : Color.WHITE, false);
        }
    }

    private void sinHallazgos(DocumentoPdf pdf) throws IOException {
        pdf.parrafo("No hay hallazgos reportados en los datos recibidos. Revisa el estado, los errores y la cobertura: esta ausencia no constituye garantía de seguridad.");
    }

    private long contar(ResultadoAnalisisHibrido resultado, EstadoRevision estado) {
        return resultado.hallazgos().stream().filter(hallazgo -> hallazgo.estadoRevision() == estado).count();
    }

    private Color color(EstadoRevision estado) {
        return switch (estado) {
            case RESPALDADO_POR_EVIDENCIA -> new Color(225, 242, 235);
            case PENDIENTE_REVISION -> new Color(255, 246, 222);
            case DESCARTADO_CON_JUSTIFICACION -> new Color(234, 236, 240);
        };
    }

    private void textos(DocumentoPdf pdf, List<String> valores) throws IOException {
        if (valores.isEmpty()) pdf.parrafo("Ninguno registrado en el resultado recibido.");
        for (String valor : valores) pdf.parrafo(valor);
    }

    private String fecha(Instant instante) {
        return instante == null ? Constantes.SIN_DATO_INFORME : FECHA.format(instante);
    }

    private String unir(List<String> valores) {
        return valores.isEmpty() ? "Ninguno reportado" : String.join(", ", valores);
    }

    private String texto(String valor) {
        return valor == null ? Constantes.SIN_DATO_INFORME : valor;
    }

    private String legible(String valor) {
        if (valor == null) return Constantes.SIN_DATO_INFORME;
        return switch (valor) {
            case "ESTATICO" -> "Estático";
            case "IA" -> "IA";
            case "AMBOS" -> "Ambos";
            case "CRITICO" -> "Crítico";
            case "RESPALDADO_POR_EVIDENCIA" -> "Respaldado por evidencia";
            case "DESCARTADO_CON_JUSTIFICACION" -> "Descartado con justificación";
            case "PENDIENTE_REVISION" -> "Pendiente de revisión";
            case "MISMA_OPERACION" -> "Misma operación";
            case "SOLO_ESTATICO" -> "Solo estático";
            case "NO_COMPARABLE" -> "No comparable";
            default -> valor.replace('_', ' ').toLowerCase(Locale.forLanguageTag("es"));
        };
    }

    private String nombreMetodo(InformeAnalisis informe) {
        return switch (informe.metodo()) {
            case ESTATICO -> "Análisis estático con Semgrep";
            case IA -> "Análisis mediante inteligencia artificial con Qwen y Ollama";
            case HIBRIDO -> "Análisis híbrido: Semgrep e inteligencia artificial";
        };
    }
}
