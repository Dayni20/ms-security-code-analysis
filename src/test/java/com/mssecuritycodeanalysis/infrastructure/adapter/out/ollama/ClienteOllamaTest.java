package com.mssecuritycodeanalysis.infrastructure.adapter.out.ollama;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withException;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.net.ConnectException;
import java.net.SocketTimeoutException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisIA;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisIA.Motivo;

class ClienteOllamaTest {

    private MockRestServiceServer servidor;
    private ClienteOllama cliente;

    @BeforeEach
    void preparar() {
        RestClient.Builder constructor = RestClient.builder().baseUrl("http://localhost:11434");
        servidor = MockRestServiceServer.bindTo(constructor).build();
        cliente = new ClienteOllama(constructor.build(), DatosPruebaIA.propiedades(), DatosPruebaIA.MAPPER);
    }

    @Test
    void obtieneDigestYEnviaLaPeticionEstructurada() throws Exception {
        servidor.expect(requestTo("http://localhost:11434/api/tags")).andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("{\"models\":[{\"name\":\"" + DatosPruebaIA.MODELO
                        + "\",\"digest\":\"abc123\"}]}", MediaType.APPLICATION_JSON));
        ConstructorPromptIA prompt = new ConstructorPromptIA(DatosPruebaIA.MAPPER, DatosPruebaIA.propiedades());
        ConstructorPromptIA.PeticionGeneracion peticion = prompt.crearPeticion(new FragmentoCodigo("a.py", "Python", 1, 1, "1 | pass\n"));
        servidor.expect(requestTo("http://localhost:11434/api/generate")).andExpect(method(HttpMethod.POST))
                .andExpect(content().json(DatosPruebaIA.MAPPER.writeValueAsString(peticion)))
                .andRespond(withSuccess(DatosPruebaIA.respuesta("{\"hallazgos\":[]}").toString(), MediaType.APPLICATION_JSON));
        assertThat(cliente.identificarModelo().digest()).isEqualTo("abc123");
        assertThat(cliente.generar(peticion).path("done").booleanValue()).isTrue();
        servidor.verify();
    }

    @Test
    void informaModeloNoInstalado() {
        servidor.expect(requestTo("http://localhost:11434/api/tags"))
                .andRespond(withSuccess("{\"models\":[]}", MediaType.APPLICATION_JSON));
        comprobarError(Motivo.MODELO_NO_ENCONTRADO);
    }

    @ParameterizedTest
    @EnumSource(value = HttpStatus.class, names = {"NOT_FOUND", "INTERNAL_SERVER_ERROR"})
    void diferenciaErroresHttp(HttpStatus estado) {
        servidor.expect(requestTo("http://localhost:11434/api/tags")).andRespond(withStatus(estado));
        comprobarError(estado == HttpStatus.NOT_FOUND ? Motivo.MODELO_NO_ENCONTRADO : Motivo.COMUNICACION_FALLIDA);
    }

    @Test
    void diferenciaTimeoutDeServicioNoDisponible() {
        servidor.expect(requestTo("http://localhost:11434/api/tags"))
                .andRespond(withException(new SocketTimeoutException("timeout")));
        comprobarError(Motivo.TIEMPO_AGOTADO);
        servidor.reset();
        servidor.expect(requestTo("http://localhost:11434/api/tags"))
                .andRespond(withException(new ConnectException("connection refused")));
        comprobarError(Motivo.NO_DISPONIBLE);
    }

    @ParameterizedTest
    @ValueSource(strings = {"no es JSON", "null", "[]", "{\"models\":[]}{}", "{\"models\":[],\"models\":[]}"})
    void rechazaJsonExternoInvalido(String contenido) {
        servidor.expect(requestTo("http://localhost:11434/api/tags"))
                .andRespond(withSuccess(contenido, MediaType.APPLICATION_JSON));
        comprobarError(Motivo.RESPUESTA_INVALIDA);
    }

    @Test
    void limitaLosBytesRecibidos() {
        servidor.expect(requestTo("http://localhost:11434/api/tags"))
                .andRespond(withSuccess(" ".repeat(1048577), MediaType.APPLICATION_JSON));
        comprobarError(Motivo.RESPUESTA_INVALIDA);
    }

    private void comprobarError(Motivo motivo) {
        assertThatThrownBy(cliente::identificarModelo).isInstanceOf(ExcepcionAnalisisIA.class)
                .extracting("motivo").isEqualTo(motivo);
        servidor.verify();
    }
}
