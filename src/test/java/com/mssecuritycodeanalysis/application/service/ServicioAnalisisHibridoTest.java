package com.mssecuritycodeanalysis.application.service;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import java.io.ByteArrayInputStream;
import java.util.List;
import org.junit.jupiter.api.Test;
import com.mssecuritycodeanalysis.application.port.out.*;
import com.mssecuritycodeanalysis.domain.model.*;
class ServicioAnalisisHibridoTest {
    @Test
    void cargaUnaVezYConservaResultadoCuandoFallaIA() {
        LectorProyectoFuente lector = mock(LectorProyectoFuente.class);
        List<ArchivoFuente> archivos = List.of(new ArchivoFuente("a.java", "class A {}", "Java"));
        when(lector.leer(any())).thenReturn(archivos);
        AnalizadorEstatico estatico = mock(AnalizadorEstatico.class);
        AnalizadorIA ia = mock(AnalizadorIA.class);
        when(estatico.analizar(archivos)).thenReturn(new ResultadoAnalisisEstatico(List.of(), List.of("Java"), List.of("Java"), List.of(), List.of("a.java"), "1", "hash"));
        when(ia.analizar(archivos)).thenThrow(new IllegalStateException());
        ResultadoAnalisisHibrido resultado = new ServicioAnalisisHibrido(new ServicioCargaProyectoFuente(lector), estatico, ia)
                .analizar("a.zip", new ByteArrayInputStream(new byte[]{1}));
        assertThat(resultado.estado()).isEqualTo("PARCIAL");
        assertThat(resultado.estatico().resultado().versionSemgrep()).isEqualTo("1");
        assertThat(resultado.ia().estado()).isEqualTo("ERROR");
        assertThat(resultado.ia().cobertura().lenguajesSinVerificar()).containsExactly("Java");
        verify(lector, times(1)).leer(any());
        verify(ia).analizar(archivos);
    }
    @Test
    void conservaErrorSiAmbosFallan() {
        LectorProyectoFuente lector = entrada -> List.of(new ArchivoFuente("a.py", "pass", "Python"));
        AnalizadorEstatico estatico = archivos -> { throw new IllegalStateException(); };
        AnalizadorIA ia = archivos -> { throw new IllegalStateException(); };
        ResultadoAnalisisHibrido resultado = new ServicioAnalisisHibrido(new ServicioCargaProyectoFuente(lector), estatico, ia)
                .analizar("a.zip", new ByteArrayInputStream(new byte[]{1}));
        assertThat(resultado.estado()).isEqualTo("ERROR");
        assertThat(resultado.hallazgos()).isEmpty();
    }
}
