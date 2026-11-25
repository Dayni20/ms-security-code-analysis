package com.mssecuritycodeanalysis.infrastructure.adapter.out.ollama;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisIA;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisIA.Motivo;
import com.mssecuritycodeanalysis.domain.model.ArchivoFuente;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisIA;
import com.mssecuritycodeanalysis.infrastructure.config.PropiedadesOllama;

class AnalizadorOllamaTest {

    private final ClienteOllama cliente = mock(ClienteOllama.class);

    @Test
    void eliminaDuplicadosDelSolapamientoYConservaMayorRiesgo() throws Exception {
        AnalizadorOllama analizador = crear(DatosPruebaIA.propiedades(16384, 4, 4000, 1, 200));
        when(cliente.generar(any())).thenReturn(DatosPruebaIA.respuesta(DatosPruebaIA.hallazgo(4, "MEDIO")),
                DatosPruebaIA.respuesta(DatosPruebaIA.hallazgo(4, "ALTO")));
        ResultadoAnalisisIA resultado = analizador.analizar(List.of(new ArchivoFuente("a.py", "a\nb\nc\nd\ne\nf", "Python")));
        assertThat(resultado.estado()).isEqualTo("COMPLETADO");
        assertThat(resultado.hallazgos()).singleElement().satisfies(hallazgo -> assertThat(hallazgo.nivelRiesgo()).isEqualTo("ALTO"));
        assertThat(resultado.fragmentos()).hasSize(2).allSatisfy(fragmento -> {
            assertThat(fragmento.estado()).isEqualTo("ANALIZADO");
            assertThat(fragmento.huellaSolicitud()).hasSize(64);
        });
        assertThat(resultado.digestModelo()).isEqualTo("digest-prueba");
        assertThat(resultado.archivosAnalizados()).containsExactly("a.py");
    }

    @Test
    void conservaResultadosPreviosYMarcaLosFragmentosPendientesTrasUnFallo() throws Exception {
        AnalizadorOllama analizador = crear(DatosPruebaIA.propiedades(16384, 2, 4000, 0, 200));
        when(cliente.generar(any())).thenReturn(DatosPruebaIA.respuesta(DatosPruebaIA.hallazgo(2, "ALTO")))
                .thenThrow(new ExcepcionAnalisisIA("Tiempo agotado", Motivo.TIEMPO_AGOTADO));
        ExcepcionAnalisisIA error = assertThrows(ExcepcionAnalisisIA.class, () -> analizador.analizar(List.of(
                new ArchivoFuente("a.py", "a\nb\nc\nd\ne", "Python"),
                new ArchivoFuente("b.ts", "codigo", "TypeScript"))));
        assertThat(error.motivo()).isEqualTo(Motivo.TIEMPO_AGOTADO);
        ResultadoAnalisisIA resultado = error.resultadoParcial();
        assertThat(resultado.estado()).isEqualTo("INCOMPLETO");
        assertThat(resultado.archivosAnalizados()).isEmpty();
        assertThat(resultado.hallazgos()).hasSize(1);
        assertThat(resultado.fragmentos()).extracting(ResultadoAnalisisIA.DetalleFragmento::estado)
                .containsExactly("ANALIZADO", "FALLIDO", "PENDIENTE", "PENDIENTE");
    }

    @Test
    void identificaLenguajesSinCoberturaSinConsultarOllama() throws Exception {
        AnalizadorOllama analizador = crearSinIdentidad(DatosPruebaIA.propiedades());
        ExcepcionAnalisisIA error = assertThrows(ExcepcionAnalisisIA.class, () -> analizador.analizar(List.of(
                new ArchivoFuente("a.cpp", "int x;", "C++"))));
        assertThat(error.motivo()).isEqualTo(Motivo.SIN_COBERTURA);
        assertThat(error.resultadoParcial().lenguajesSinCobertura()).containsExactly("C++");
        verifyNoInteractions(cliente);
    }

    @Test
    void noPresentaUnProyectoConCoberturaParcialComoCompletado() throws Exception {
        AnalizadorOllama analizador = crear(DatosPruebaIA.propiedades());
        when(cliente.generar(any())).thenReturn(DatosPruebaIA.respuesta("{\"hallazgos\":[]}"));
        ExcepcionAnalisisIA error = assertThrows(ExcepcionAnalisisIA.class, () -> analizador.analizar(List.of(
                new ArchivoFuente("a.py", "pass", "Python"), new ArchivoFuente("b.php", "<?php", "PHP"))));
        assertThat(error.resultadoParcial().estado()).isEqualTo("INCOMPLETO");
        assertThat(error.resultadoParcial().archivosAnalizados()).containsExactly("a.py");
        assertThat(error.resultadoParcial().lenguajesSinCobertura()).containsExactly("PHP");
    }

    @Test
    void noGeneraInferenciasParaArchivosVacios() throws Exception {
        ResultadoAnalisisIA resultado = crear(DatosPruebaIA.propiedades()).analizar(List.of(new ArchivoFuente("a.py", " \n", "Python")));
        assertThat(resultado.estado()).isEqualTo("COMPLETADO");
        assertThat(resultado.hallazgos()).isEmpty();
        verify(cliente, never()).generar(any());
    }

    @Test
    void registraTodosLosArchivosPendientesSiOllamaNoEstaDisponible() throws Exception {
        AnalizadorOllama analizador = crearSinIdentidad(DatosPruebaIA.propiedades());
        when(cliente.identificarModelo()).thenThrow(new ExcepcionAnalisisIA("No disponible", Motivo.NO_DISPONIBLE));
        ExcepcionAnalisisIA error = assertThrows(ExcepcionAnalisisIA.class, () -> analizador.analizar(List.of(
                new ArchivoFuente("a.py", "pass", "Python"))));
        assertThat(error.resultadoParcial().estado()).isEqualTo("INCOMPLETO");
        assertThat(error.resultadoParcial().fragmentos()).singleElement()
                .satisfies(fragmento -> assertThat(fragmento.estado()).isEqualTo("PENDIENTE"));
        verify(cliente, never()).generar(any());
    }

    private AnalizadorOllama crear(PropiedadesOllama propiedades) throws Exception {
        when(cliente.identificarModelo()).thenReturn(new ClienteOllama.IdentidadModelo(DatosPruebaIA.MODELO, "digest-prueba"));
        return crearSinIdentidad(propiedades);
    }

    private AnalizadorOllama crearSinIdentidad(PropiedadesOllama propiedades) throws Exception {
        ConstructorPromptIA prompt = new ConstructorPromptIA(DatosPruebaIA.MAPPER, propiedades);
        return new AnalizadorOllama(propiedades, cliente, prompt, new FragmentadorCodigo(propiedades, prompt),
                new InterpreteRespuestaIA(DatosPruebaIA.MAPPER));
    }
}
