package com.mssecuritycodeanalysis.infrastructure.adapter.out.ollama;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.http.HttpTimeoutException;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisIA;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisIA.Motivo;
import com.mssecuritycodeanalysis.domain.Constantes;
import com.mssecuritycodeanalysis.infrastructure.adapter.out.ollama.ConstructorPromptIA.PeticionGeneracion;
import com.mssecuritycodeanalysis.infrastructure.config.PropiedadesOllama;

public class ClienteOllama {

    private final RestClient cliente;
    private final PropiedadesOllama propiedades;
    private final ObjectReader lector;

    public ClienteOllama(RestClient cliente, PropiedadesOllama propiedades, ObjectMapper mapper) {
        this.cliente = cliente;
        this.propiedades = propiedades;
        this.lector = mapper.reader().with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                .with(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    }

    public IdentidadModelo identificarModelo() {
        try {
            JsonNode respuesta = cliente.get().uri(Constantes.RUTA_MODELOS_OLLAMA)
                    .accept(MediaType.APPLICATION_JSON).exchange((solicitud, datos) -> leerRespuesta(datos));
            JsonNode modelos = respuesta.get(Constantes.CAMPO_MODELOS_OLLAMA);
            if (modelos == null || !modelos.isArray()) {
                throw respuestaInvalida();
            }
            for (JsonNode modelo : modelos) {
                String nombre = modelo.path(Constantes.CAMPO_NOMBRE_MODELO_OLLAMA).asText();
                String identificador = modelo.path(Constantes.CAMPO_MODELO_OLLAMA).asText();
                if (propiedades.modelo().equals(nombre) || propiedades.modelo().equals(identificador)) {
                    JsonNode digest = modelo.get(Constantes.CAMPO_DIGEST_MODELO);
                    if (digest != null && (!digest.isTextual() || digest.textValue().isBlank())) {
                        throw respuestaInvalida();
                    }
                    return new IdentidadModelo(propiedades.modelo(), digest == null ? null : digest.textValue());
                }
            }
            throw new ExcepcionAnalisisIA(Constantes.MENSAJE_MODELO_NO_ENCONTRADO, Motivo.MODELO_NO_ENCONTRADO);
        } catch (RestClientException excepcion) {
            throw convertirErrorComunicacion(excepcion);
        }
    }

    public JsonNode generar(PeticionGeneracion peticion) {
        try {
            return cliente.post().uri(Constantes.RUTA_GENERACION_OLLAMA)
                    .contentType(MediaType.APPLICATION_JSON).accept(MediaType.APPLICATION_JSON)
                    .body(peticion).exchange((solicitud, respuesta) -> leerRespuesta(respuesta));
        } catch (RestClientException excepcion) {
            throw convertirErrorComunicacion(excepcion);
        }
    }

    private JsonNode leerRespuesta(ClientHttpResponse respuesta) throws IOException {
        if (respuesta.getStatusCode().value() == HttpStatus.NOT_FOUND.value()) {
            throw new ExcepcionAnalisisIA(Constantes.MENSAJE_MODELO_NO_ENCONTRADO, Motivo.MODELO_NO_ENCONTRADO);
        }
        if (!respuesta.getStatusCode().is2xxSuccessful()) {
            throw new ExcepcionAnalisisIA(Constantes.MENSAJE_OLLAMA_NO_DISPONIBLE, Motivo.COMUNICACION_FALLIDA);
        }
        byte[] contenido = respuesta.getBody().readNBytes(propiedades.maxBytesRespuesta());
        if (respuesta.getBody().read() != -1) {
            throw respuestaInvalida();
        }
        try {
            JsonNode documento = lector.readTree(contenido);
            if (documento == null || !documento.isObject()) {
                throw respuestaInvalida();
            }
            return documento;
        } catch (IOException excepcion) {
            throw new ExcepcionAnalisisIA(Constantes.MENSAJE_RESPUESTA_IA_INVALIDA, Motivo.RESPUESTA_INVALIDA, excepcion);
        }
    }

    private ExcepcionAnalisisIA convertirErrorComunicacion(RestClientException excepcion) {
        Throwable causa = excepcion;
        while (causa != null) {
            if (causa instanceof SocketTimeoutException || causa instanceof HttpTimeoutException) {
                return new ExcepcionAnalisisIA(Constantes.MENSAJE_TIEMPO_OLLAMA_AGOTADO,
                        Motivo.TIEMPO_AGOTADO, excepcion);
            }
            causa = causa.getCause();
        }
        Motivo motivo = excepcion instanceof ResourceAccessException ? Motivo.NO_DISPONIBLE : Motivo.COMUNICACION_FALLIDA;
        return new ExcepcionAnalisisIA(Constantes.MENSAJE_OLLAMA_NO_DISPONIBLE, motivo, excepcion);
    }

    private ExcepcionAnalisisIA respuestaInvalida() {
        return new ExcepcionAnalisisIA(Constantes.MENSAJE_RESPUESTA_IA_INVALIDA, Motivo.RESPUESTA_INVALIDA);
    }

    public record IdentidadModelo(String nombre, String digest) {
    }
}
