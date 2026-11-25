package com.mssecuritycodeanalysis.infrastructure.adapter.in.rest;

import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.util.Set;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.mssecuritycodeanalysis.domain.Constantes;
import com.mssecuritycodeanalysis.domain.model.InformeAnalisis;
import com.mssecuritycodeanalysis.domain.model.InformeAnalisis.Metodo;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisEstatico;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisHibrido;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisIA;

public class LectorSolicitudInforme {
    public static final int MAX_BYTES = 4 * 1024 * 1024;
    private static final Set<String> PARAMETROS_POSITIVOS = Set.of("contexto", "maxTokensGeneracion", "maxLineasFragmento",
            "maxCaracteresFragmento", "margenTokens", "maxFragmentosPorArchivo");
    private final ObjectMapper mapper;

    public LectorSolicitudInforme(ObjectMapper mapper) {
        this.mapper = mapper.copy();
        this.mapper.getFactory().setStreamReadConstraints(StreamReadConstraints.builder()
                .maxNestingDepth(32).maxStringLength(100000).build());
    }

    public InformeAnalisis leer(InputStream entrada) throws IOException {
        byte[] bytes = entrada.readNBytes(MAX_BYTES + 1);
        exigir(bytes.length <= MAX_BYTES);
        ObjectReader lector = mapper.reader().with(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
                .with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
        JsonNode solicitud = lector.readTree(bytes);
        exigir(solicitud != null && solicitud.isObject());
        estructura(solicitud, 0);
        String nombre = texto(solicitud, "nombreArchivoZip");
        exigir(nombre.length() <= 255 && nombre.chars().noneMatch(Character::isISOControl));
        Metodo metodo = switch (texto(solicitud, "metodo")) {
            case "static" -> Metodo.ESTATICO;
            case "ai" -> Metodo.IA;
            case "hybrid" -> Metodo.HIBRIDO;
            default -> throw invalida();
        };
        JsonNode respuesta = solicitud.get("respuesta");
        exigir(respuesta != null && respuesta.isObject());
        String estado = texto(respuesta, "estado");
        exigir(Set.of("COMPLETADO", "PARCIAL", "INCOMPLETO", "ERROR").contains(estado));
        if (respuesta.hasNonNull("nombreArchivoZip")) exigir(nombre.equals(texto(respuesta, "nombreArchivoZip")));
        JsonNode resultado = respuesta.get("resultado");
        exigir(resultado != null && resultado.isObject());
        validarResultado(resultado, metodo);
        Long tiempo = null;
        if (solicitud.hasNonNull("tiempoSolicitudMilisegundos")) {
            JsonNode valor = solicitud.get("tiempoSolicitudMilisegundos");
            exigir(valor.isIntegralNumber() && valor.canConvertToLong() && valor.longValue() >= 0);
            tiempo = valor.longValue();
        }
        Instant fecha = null;
        if (solicitud.hasNonNull("fechaAnalisis")) {
            try { fecha = Instant.parse(texto(solicitud, "fechaAnalisis")); }
            catch (java.time.DateTimeException excepcion) { throw invalida(); }
        }
        if (metodo != Metodo.ESTATICO) exigir(estado.equals(texto(resultado, "estado")));
        return new InformeAnalisis(metodo, nombre, estado, fecha, Instant.now(), tiempo,
                opcional(respuesta, "motivo"), opcional(respuesta, "error"),
                metodo == Metodo.ESTATICO ? convertir(resultado, ResultadoAnalisisEstatico.class) : null,
                metodo == Metodo.IA ? convertir(resultado, ResultadoAnalisisIA.class) : null,
                metodo == Metodo.HIBRIDO ? convertir(resultado, ResultadoAnalisisHibrido.class) : null);
    }

    private <T> T convertir(JsonNode nodo, Class<T> tipo) throws IOException {
        return mapper.readerFor(tipo).with(DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES)
                .with(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
                .with(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES).readValue(nodo);
    }

    private void validarResultado(JsonNode resultado, Metodo metodo) {
        arregloTextos(resultado.get("archivosAnalizados"));
        JsonNode hallazgos = resultado.get("hallazgos");
        exigir(hallazgos != null && hallazgos.isArray() && hallazgos.size() <= 1000);
        for (JsonNode hallazgo : hallazgos) {
            validarHallazgo(hallazgo, metodo == Metodo.HIBRIDO);
            if (metodo != Metodo.HIBRIDO) exigir(texto(hallazgo, "metodoDeteccion").equals(metodo.name()));
        }
        if (metodo == Metodo.HIBRIDO) {
            validarMetodo(resultado.get("estatico"), Metodo.ESTATICO);
            validarMetodo(resultado.get("ia"), Metodo.IA);
            JsonNode tiempos = resultado.get("tiempos");
            exigir(tiempos != null && tiempos.isObject());
            tiempos.properties().forEach(campo -> {
                if (!campo.getKey().equals("concurrente")) exigir(campo.getValue().isIntegralNumber()
                        && campo.getValue().canConvertToLong() && campo.getValue().longValue() >= 0);
            });
        } else {
            arregloTextos(resultado.get("lenguajesReconocidos"));
            arregloTextos(resultado.get(metodo == Metodo.ESTATICO ? "lenguajesConReglas" : "lenguajesConCobertura"));
            arregloTextos(resultado.get(metodo == Metodo.ESTATICO ? "lenguajesSinReglas" : "lenguajesSinCobertura"));
            if (metodo == Metodo.ESTATICO) {
                texto(resultado, "versionSemgrep");
                texto(resultado, "huellaReglas");
            } else {
                texto(resultado, "modelo");
                texto(resultado, "versionPrompt");
                texto(resultado, "huellaPrompt");
                exigir(texto(resultado, "metodoDeteccion").equals("IA"));
                exigir(Set.of("COMPLETADO", "INCOMPLETO").contains(texto(resultado, "estado")));
                JsonNode parametros = resultado.get("parametros");
                exigir(parametros != null && parametros.isObject());
                for (String campo : PARAMETROS_POSITIVOS) entero(parametros.get(campo), 1);
                entero(parametros.get("lineasSolapamiento"), 0);
                JsonNode semilla = parametros.get("semilla");
                exigir(semilla != null && semilla.isIntegralNumber() && semilla.canConvertToLong());
                JsonNode temperatura = parametros.get("temperatura");
                exigir(temperatura != null && temperatura.isNumber() && Double.isFinite(temperatura.doubleValue())
                        && temperatura.doubleValue() >= 0 && temperatura.doubleValue() <= 2);
            }
        }
    }

    private void validarMetodo(JsonNode metodo, Metodo tipo) {
        exigir(metodo != null && metodo.isObject());
        exigir(Set.of("COMPLETADO", "PARCIAL", "ERROR").contains(texto(metodo, "estado")));
        JsonNode tiempo = metodo.get("tiempoMilisegundos");
        exigir(tiempo != null && tiempo.isIntegralNumber() && tiempo.canConvertToLong() && tiempo.longValue() >= 0);
        exigir(metodo.hasNonNull("cobertura") && metodo.get("cobertura").isObject());
        for (JsonNode campo : metodo.get("cobertura")) arregloTextos(campo);
        if (metodo.hasNonNull("resultado")) validarResultado(metodo.get("resultado"), tipo);
        else exigir(!texto(metodo, "estado").equals("COMPLETADO"));
    }

    private void validarHallazgo(JsonNode hallazgo, boolean hibrido) {
        exigir(hallazgo.isObject());
        texto(hallazgo, "descripcion");
        texto(hallazgo, "rutaRelativa");
        JsonNode linea = hallazgo.get("linea");
        exigir(linea != null && linea.isIntegralNumber() && linea.canConvertToInt() && linea.intValue() >= 1);
        exigir(Constantes.NIVELES_RIESGO_IA.contains(texto(hallazgo, "nivelRiesgo")));
        exigir(Set.of("ESTATICO", "IA", "AMBOS").contains(texto(hallazgo, "metodoDeteccion")));
        if (hibrido) {
            exigir(Constantes.CWE_ADMITIDAS_IA.contains(texto(hallazgo, "cwe")));
            texto(hallazgo, "justificacion");
            texto(hallazgo, "estadoRevision");
            texto(hallazgo, "estadoCorrelacion");
            exigir(hallazgo.hasNonNull("evidencia") && hallazgo.get("evidencia").isArray());
            exigir(hallazgo.hasNonNull("originales") && hallazgo.get("originales").isArray());
            for (JsonNode evidencia : hallazgo.get("evidencia")) {
                exigir(evidencia.isObject());
                texto(evidencia, "descripcion");
                texto(evidencia, "tipo");
                entero(evidencia.get("lineaInicio"), 1);
                entero(evidencia.get("lineaFin"), 1);
                exigir(evidencia.get("lineaFin").intValue() >= evidencia.get("lineaInicio").intValue());
            }
            for (JsonNode original : hallazgo.get("originales")) validarHallazgo(original, false);
        } else {
            arregloTextos(hallazgo.get("cwe"));
            for (JsonNode cwe : hallazgo.get("cwe")) exigir(Constantes.CWE_ADMITIDAS_IA.contains(cwe.textValue()));
        }
    }

    private int estructura(JsonNode nodo, int elementos) {
        int total = elementos + 1;
        if (nodo.isTextual()) exigir(nodo.textValue().length() <= 100000);
        for (JsonNode hijo : nodo) {
            total = estructura(hijo, total);
            exigir(total <= 50000);
        }
        return total;
    }

    private void arregloTextos(JsonNode nodo) {
        exigir(nodo != null && nodo.isArray());
        for (JsonNode valor : nodo) exigir(valor.isTextual() && !valor.textValue().isBlank());
    }

    private String texto(JsonNode nodo, String campo) {
        JsonNode valor = nodo.get(campo);
        exigir(valor != null && valor.isTextual() && !valor.textValue().isBlank());
        return valor.textValue();
    }

    private String opcional(JsonNode nodo, String campo) {
        if (!nodo.hasNonNull(campo)) return null;
        exigir(nodo.get(campo).isTextual());
        return nodo.get(campo).textValue();
    }

    private void exigir(boolean condicion) {
        if (!condicion) throw invalida();
    }

    private void entero(JsonNode nodo, int minimo) {
        exigir(nodo != null && nodo.isIntegralNumber() && nodo.canConvertToInt() && nodo.intValue() >= minimo);
    }


    private IllegalArgumentException invalida() {
        return new IllegalArgumentException(Constantes.MENSAJE_SOLICITUD_PDF_INVALIDA);
    }
}
