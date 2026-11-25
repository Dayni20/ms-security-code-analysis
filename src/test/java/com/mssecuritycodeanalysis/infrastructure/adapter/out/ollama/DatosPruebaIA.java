package com.mssecuritycodeanalysis.infrastructure.adapter.out.ollama;

import java.net.URI;
import java.util.Set;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mssecuritycodeanalysis.infrastructure.config.PropiedadesOllama;

final class DatosPruebaIA {

    static final ObjectMapper MAPPER = new ObjectMapper();
    static final String MODELO = "qwen2.5-coder:7b-instruct";

    static PropiedadesOllama propiedades(int contexto, int lineas, int caracteres, int solapamiento, int fragmentos) {
        return new PropiedadesOllama(URI.create("http://localhost:11434"), MODELO, 0, contexto, 1024, 0,
                lineas, caracteres, solapamiento, 512, fragmentos, 5, 300, 1048576,
                Set.of("Java", "Python", "JavaScript", "TypeScript"), 900);
    }

    static PropiedadesOllama propiedades() {
        return propiedades(16384, 80, 4000, 10, 200);
    }

    static ObjectNode respuesta(String contenido) {
        return MAPPER.createObjectNode().put("model", MODELO).put("done", true)
                .put("done_reason", "stop").put("response", contenido);
    }

    static String hallazgo(int linea, String riesgo) {
        return """
                {"hallazgos":[{"cwe":"CWE-89","descripcion":"Entrada externa concatenada en SQL",
                "linea":%d,"nivelRiesgo":"%s"}]}
                """.formatted(linea, riesgo);
    }

    private DatosPruebaIA() {
    }
}
