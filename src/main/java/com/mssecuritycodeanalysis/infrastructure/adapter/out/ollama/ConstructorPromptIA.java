package com.mssecuritycodeanalysis.infrastructure.adapter.out.ollama;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mssecuritycodeanalysis.domain.Constantes;
import com.mssecuritycodeanalysis.infrastructure.config.PropiedadesOllama;

public class ConstructorPromptIA {

    private final ObjectMapper mapper;
    private final PropiedadesOllama propiedades;
    private final String instrucciones;
    private final ObjectNode esquemaBase;
    private final String huellaPrompt;

    public ConstructorPromptIA(ObjectMapper mapper, PropiedadesOllama propiedades) throws IOException {
        this.mapper = mapper;
        this.propiedades = propiedades;
        this.instrucciones = leerRecurso(Constantes.RECURSO_PROMPT_IA);
        JsonNode esquema = mapper.readTree(leerRecurso(Constantes.RECURSO_ESQUEMA_IA));
        if (!esquema.isObject()) {
            throw new IOException(Constantes.MENSAJE_CONFIGURACION_IA_INVALIDA);
        }
        this.esquemaBase = (ObjectNode) esquema;
        this.huellaPrompt = calcularHuella(instrucciones + Constantes.SEPARADOR_HUELLA_PROMPT
                + mapper.writeValueAsString(esquemaBase));
    }

    public PeticionGeneracion crearPeticion(FragmentoCodigo fragmento) {
        return new PeticionGeneracion(propiedades.modelo(), instrucciones, crearPrompt(fragmento),
                false, crearEsquema(fragmento), new OpcionesGeneracion(propiedades.temperatura(),
                propiedades.contexto(), propiedades.maxTokensGeneracion(), propiedades.semilla()),
                propiedades.mantenerModeloSegundos());
    }

    public boolean cabeEnContexto(FragmentoCodigo fragmento) {
        long bytesEntrada = instrucciones.getBytes(StandardCharsets.UTF_8).length
                + (long) crearPrompt(fragmento).getBytes(StandardCharsets.UTF_8).length;
        long presupuesto = (long) propiedades.contexto() - propiedades.maxTokensGeneracion() - propiedades.margenTokens();
        return bytesEntrada <= presupuesto;
    }

    public String huellaPrompt() {
        return huellaPrompt;
    }

    public String huellaSolicitud(FragmentoCodigo fragmento) {
        return calcularHuella(instrucciones + Constantes.SEPARADOR_HUELLA_PROMPT + crearPrompt(fragmento));
    }

    private String crearPrompt(FragmentoCodigo fragmento) {
        ObjectNode datos = mapper.createObjectNode();
        datos.put(Constantes.CAMPO_ARCHIVO_PROMPT, fragmento.rutaRelativa());
        datos.put(Constantes.CAMPO_LENGUAJE_PROMPT, fragmento.lenguaje());
        datos.put(Constantes.CAMPO_INICIO_PROMPT, fragmento.lineaInicio());
        datos.put(Constantes.CAMPO_FIN_PROMPT, fragmento.lineaFin());
        datos.put(Constantes.CAMPO_CODIGO_PROMPT, fragmento.codigoNumerado());
        try {
            return Constantes.FORMATO_PROMPT_IA.formatted(mapper.writeValueAsString(datos));
        } catch (IOException excepcion) {
            throw new IllegalStateException(Constantes.MENSAJE_CONFIGURACION_IA_INVALIDA, excepcion);
        }
    }

    private ObjectNode crearEsquema(FragmentoCodigo fragmento) {
        ObjectNode esquema = esquemaBase.deepCopy();
        ObjectNode linea = (ObjectNode) esquema.path(Constantes.CAMPO_PROPIEDADES_ESQUEMA)
                .path(Constantes.CAMPO_HALLAZGOS_IA).path(Constantes.CAMPO_ELEMENTOS_ESQUEMA)
                .path(Constantes.CAMPO_PROPIEDADES_ESQUEMA).path(Constantes.CAMPO_LINEA_IA);
        linea.put(Constantes.CAMPO_MINIMO_ESQUEMA, fragmento.lineaInicio());
        linea.put(Constantes.CAMPO_MAXIMO_ESQUEMA, fragmento.lineaFin());
        return esquema;
    }

    private String leerRecurso(String ruta) throws IOException {
        try (InputStream entrada = ConstructorPromptIA.class.getResourceAsStream(ruta)) {
            if (entrada == null) {
                throw new IOException(Constantes.MENSAJE_CONFIGURACION_IA_INVALIDA);
            }
            return new String(entrada.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private String calcularHuella(String contenido) {
        try {
            byte[] huella = MessageDigest.getInstance(Constantes.ALGORITMO_HUELLA_REGLAS)
                    .digest(contenido.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(huella);
        } catch (NoSuchAlgorithmException excepcion) {
            throw new IllegalStateException(Constantes.MENSAJE_CONFIGURACION_IA_INVALIDA, excepcion);
        }
    }

    public record PeticionGeneracion(@JsonProperty(Constantes.CAMPO_MODELO_OLLAMA) String modelo,
            @JsonProperty(Constantes.CAMPO_SISTEMA_OLLAMA) String sistema,
            @JsonProperty(Constantes.CAMPO_PROMPT_OLLAMA) String prompt,
            @JsonProperty(Constantes.CAMPO_STREAM_OLLAMA) boolean stream,
            @JsonProperty(Constantes.CAMPO_FORMATO_OLLAMA) JsonNode formato,
            @JsonProperty(Constantes.CAMPO_OPCIONES_OLLAMA) OpcionesGeneracion opciones,
            @JsonProperty(Constantes.CAMPO_PERMANENCIA_OLLAMA) int mantenerModeloSegundos) {
    }

    public record OpcionesGeneracion(@JsonProperty(Constantes.CAMPO_TEMPERATURA_OLLAMA) double temperatura,
            @JsonProperty(Constantes.CAMPO_CONTEXTO_OLLAMA) int contexto,
            @JsonProperty(Constantes.CAMPO_GENERACION_OLLAMA) int maxTokens,
            @JsonProperty(Constantes.CAMPO_SEMILLA_OLLAMA) long semilla) {
    }
}
