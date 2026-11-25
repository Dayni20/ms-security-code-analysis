package com.mssecuritycodeanalysis.infrastructure.adapter.out.ollama;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisIA;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisIA.Motivo;
import com.mssecuritycodeanalysis.domain.model.HallazgoSeguridad;

class InterpreteRespuestaIATest {

    private final InterpreteRespuestaIA interprete = new InterpreteRespuestaIA(DatosPruebaIA.MAPPER);
    private final FragmentoCodigo fragmento = new FragmentoCodigo("src/Consulta.java", "Java", 10, 20, "10 | codigo\n");

    @Test
    void interpretaHallazgoConRutaDelBackend() {
        List<HallazgoSeguridad> resultado = interpretar(DatosPruebaIA.hallazgo(15, "ALTO"));
        assertThat(resultado).singleElement().satisfies(hallazgo -> {
            assertThat(hallazgo.rutaRelativa()).isEqualTo("src/Consulta.java");
            assertThat(hallazgo.linea()).isEqualTo(15);
            assertThat(hallazgo.cwe()).containsExactly("CWE-89");
            assertThat(hallazgo.metodoDeteccion()).isEqualTo("IA");
        });
    }

    @Test
    void aceptaAnalisisFinalizadoSinHallazgos() {
        assertThat(interpretar("{\"hallazgos\":[]}")).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "texto", "```json\n{\"hallazgos\":[]}\n```", "null", "[]", "{}",
            "{\"hallazgos\":null}", "{\"hallazgos\":[],\"extra\":1}",
            "{\"hallazgos\":[],\"hallazgos\":[]}", "{\"hallazgos\":[]} {}"})
    void rechazaRespuestaInvalidaSinConvertirlaEnListaVacia(String contenido) {
        assertThatThrownBy(() -> interpretar(contenido)).isInstanceOf(ExcepcionAnalisisIA.class)
                .extracting("motivo").isEqualTo(Motivo.RESPUESTA_INVALIDA);
    }

    @ParameterizedTest
    @ValueSource(strings = {"0", "9", "21", "999999999999999", "15.5", "\"15\"", "null"})
    void rechazaLineasInexistentesOFueraDelFragmento(String linea) {
        String contenido = DatosPruebaIA.hallazgo(15, "ALTO").replace("\"linea\":15", "\"linea\":" + linea);
        assertThatThrownBy(() -> interpretar(contenido)).isInstanceOf(ExcepcionAnalisisIA.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"CWE-79", "BASTANTE_ALTO", "descripcion-vacia", "ruta-inventada"})
    void rechazaHallazgosQueIncumplenElEsquema(String caso) {
        String contenido = DatosPruebaIA.hallazgo(15, "ALTO");
        contenido = switch (caso) {
            case "CWE-79" -> contenido.replace("CWE-89", caso);
            case "BASTANTE_ALTO" -> contenido.replace("ALTO", caso);
            case "descripcion-vacia" -> contenido.replace("Entrada externa concatenada en SQL", "  ");
            default -> contenido.replace("\"linea\":15", "\"ruta\":\"otra.java\",\"linea\":15");
        };
        String respuesta = contenido;
        assertThatThrownBy(() -> interpretar(respuesta)).isInstanceOf(ExcepcionAnalisisIA.class);
    }

    @Test
    void rechazaGeneracionesIncompletasYContextosExcedidos() {
        ObjectNode respuesta = DatosPruebaIA.respuesta("{\"hallazgos\":[]}");
        respuesta.put("done", false);
        comprobarGeneracionIncompleta(respuesta);
        respuesta.put("done", true).put("done_reason", "length");
        comprobarGeneracionIncompleta(respuesta);
        respuesta.put("done_reason", "stop").put("prompt_eval_count", 4000);
        comprobarGeneracionIncompleta(respuesta);
    }

    @Test
    void rechazaUnModeloDiferenteAlConfigurado() {
        ObjectNode respuesta = DatosPruebaIA.respuesta("{\"hallazgos\":[]}").put("model", "otro");
        assertThatThrownBy(() -> interprete.interpretar(respuesta, fragmento, DatosPruebaIA.MODELO, 3072))
                .isInstanceOf(ExcepcionAnalisisIA.class).extracting("motivo").isEqualTo(Motivo.RESPUESTA_INVALIDA);
    }

    private List<HallazgoSeguridad> interpretar(String contenido) {
        return interprete.interpretar(DatosPruebaIA.respuesta(contenido), fragmento, DatosPruebaIA.MODELO, 3072);
    }

    private void comprobarGeneracionIncompleta(ObjectNode respuesta) {
        assertThatThrownBy(() -> interprete.interpretar(respuesta, fragmento, DatosPruebaIA.MODELO, 3072))
                .isInstanceOf(ExcepcionAnalisisIA.class).extracting("motivo").isEqualTo(Motivo.GENERACION_INCOMPLETA);
    }
}
