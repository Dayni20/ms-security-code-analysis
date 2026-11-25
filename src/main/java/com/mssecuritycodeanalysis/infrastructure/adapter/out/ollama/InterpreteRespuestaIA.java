package com.mssecuritycodeanalysis.infrastructure.adapter.out.ollama;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisIA;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisIA.Motivo;
import com.mssecuritycodeanalysis.domain.Constantes;
import com.mssecuritycodeanalysis.domain.model.HallazgoSeguridad;

public class InterpreteRespuestaIA {

    private final ObjectReader lector;

    public InterpreteRespuestaIA(ObjectMapper mapper) {
        this.lector = mapper.reader().with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                .with(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    }

    public List<HallazgoSeguridad> interpretar(JsonNode respuesta, FragmentoCodigo fragmento,
            String modeloEsperado, int presupuestoEntrada) {
        validarGeneracion(respuesta, modeloEsperado, presupuestoEntrada);
        try {
            JsonNode contenido = lector.readTree(leerTexto(respuesta, Constantes.CAMPO_RESPUESTA_OLLAMA));
            if (contenido == null || !contenido.isObject() || contenido.size() != 1) {
                throw respuestaInvalida();
            }
            JsonNode hallazgos = contenido.get(Constantes.CAMPO_HALLAZGOS_IA);
            if (hallazgos == null || !hallazgos.isArray() || hallazgos.size() > 20) {
                throw respuestaInvalida();
            }
            List<HallazgoSeguridad> resultado = new ArrayList<>();
            for (JsonNode hallazgo : hallazgos) {
                resultado.add(leerHallazgo(hallazgo, fragmento));
            }
            return List.copyOf(resultado);
        } catch (IOException excepcion) {
            throw new ExcepcionAnalisisIA(Constantes.MENSAJE_RESPUESTA_IA_INVALIDA, Motivo.RESPUESTA_INVALIDA, excepcion);
        }
    }

    private void validarGeneracion(JsonNode respuesta, String modeloEsperado, int presupuestoEntrada) {
        if (respuesta == null || !respuesta.isObject()) {
            throw respuestaInvalida();
        }
        JsonNode finalizado = respuesta.get(Constantes.CAMPO_FINALIZADO_OLLAMA);
        if (finalizado == null || !finalizado.isBoolean() || !finalizado.booleanValue()) {
            throw generacionIncompleta();
        }
        JsonNode motivo = respuesta.get(Constantes.CAMPO_MOTIVO_FINALIZACION);
        if (motivo == null || !Constantes.FINALIZACION_CORRECTA_OLLAMA.equals(motivo.asText())) {
            throw generacionIncompleta();
        }
        if (!modeloEsperado.equals(leerTexto(respuesta, Constantes.CAMPO_MODELO_OLLAMA))) {
            throw respuestaInvalida();
        }
        JsonNode tokens = respuesta.get(Constantes.CAMPO_TOKENS_ENTRADA);
        if (tokens != null && (!tokens.isIntegralNumber() || !tokens.canConvertToInt()
                || tokens.intValue() < 0 || tokens.intValue() > presupuestoEntrada)) {
            throw generacionIncompleta();
        }
    }

    private HallazgoSeguridad leerHallazgo(JsonNode hallazgo, FragmentoCodigo fragmento) {
        if (!hallazgo.isObject() || hallazgo.size() != 4) {
            throw respuestaInvalida();
        }
        String cwe = leerTexto(hallazgo, Constantes.CAMPO_CWE_IA);
        String descripcion = leerTexto(hallazgo, Constantes.CAMPO_DESCRIPCION_IA);
        String riesgo = leerTexto(hallazgo, Constantes.CAMPO_RIESGO_IA);
        if (!Constantes.CWE_ADMITIDAS_IA.contains(cwe) || !Constantes.NIVELES_RIESGO_IA.contains(riesgo)) {
            throw respuestaInvalida();
        }
        JsonNode linea = hallazgo.get(Constantes.CAMPO_LINEA_IA);
        if (linea == null || !linea.isIntegralNumber() || !linea.canConvertToInt()) {
            throw respuestaInvalida();
        }
        if (linea.intValue() < fragmento.lineaInicio() || linea.intValue() > fragmento.lineaFin()) {
            throw respuestaInvalida();
        }
        return new HallazgoSeguridad(Constantes.PREFIJO_HALLAZGO_IA + cwe, descripcion, List.of(cwe),
                fragmento.rutaRelativa(), linea.intValue(), riesgo, Constantes.METODO_DETECCION_IA);
    }

    private String leerTexto(JsonNode objeto, String campo) {
        JsonNode valor = objeto.get(campo);
        if (valor == null || !valor.isTextual() || valor.textValue().isBlank()) {
            throw respuestaInvalida();
        }
        return valor.textValue();
    }

    private ExcepcionAnalisisIA respuestaInvalida() {
        return new ExcepcionAnalisisIA(Constantes.MENSAJE_RESPUESTA_IA_INVALIDA, Motivo.RESPUESTA_INVALIDA);
    }

    private ExcepcionAnalisisIA generacionIncompleta() {
        return new ExcepcionAnalisisIA(Constantes.MENSAJE_GENERACION_IA_INCOMPLETA, Motivo.GENERACION_INCOMPLETA);
    }
}
