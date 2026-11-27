package com.mssecuritycodeanalysis.infrastructure.adapter.out.semgrep;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisEstatico;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisEstatico.Motivo;
import com.mssecuritycodeanalysis.domain.model.ArchivoFuente;
import com.mssecuritycodeanalysis.infrastructure.config.PropiedadesSemgrep;
import com.mssecuritycodeanalysis.infrastructure.config.PropiedadesSemgrep.ModoEjecucion;

class AnalizadorSemgrepTest {
    @TempDir Path temporal;
    private final AtomicReference<Path> trabajo = new AtomicReference<>();
    private final AtomicInteger intentos = new AtomicInteger();
    private EjecutorSemgrep ejecutor;
    private AnalizadorSemgrep analizador;
    private final List<ArchivoFuente> archivos = List.of(new ArchivoFuente("Unidad.java", "class Unidad {}", "Java"));

    @BeforeEach
    void preparar() throws Exception {
        Path reglas = temporal.resolve("reglas.yaml");
        Files.writeString(reglas, "rules:\n  - id: prueba.java\n    languages: [java]\n");
        PropiedadesSemgrep propiedades = new PropiedadesSemgrep("semgrep", reglas, 60, 1024,
                ModoEjecucion.NATIVO, "wsl.exe", "Ubuntu", "semgrep");
        ejecutor = mock(EjecutorSemgrep.class);
        when(ejecutor.ejecutar(any(), any(), any())).thenAnswer(invocacion -> {
            trabajo.set(invocacion.getArgument(0));
            return new EjecutorSemgrep.SalidaSemgrep(new byte[0], trabajo.get().toString());
        });
        InterpreteResultadoSemgrep interprete = mock(InterpreteResultadoSemgrep.class);
        when(interprete.interpretar(any(), any(), any(), anySet(), anySet())).thenReturn(
                new InterpreteResultadoSemgrep.LecturaSemgrep(List.of(), List.of("Unidad.java"), "simulada"));
        analizador = new AnalizadorSemgrep(propiedades, temporal.resolve("trabajos"), ejecutor, interprete);
    }

    private MockedStatic<Files> bloquearCarpeta(int fallos) {
        return mockStatic(Files.class, invocacion -> {
            if (invocacion.getMethod().getName().equals("deleteIfExists")
                    && invocacion.getArgument(0).equals(trabajo.get())
                    && intentos.incrementAndGet() <= fallos) {
                throw new AccessDeniedException(trabajo.get().toString(), null, "Bloqueo simulado");
            }
            return invocacion.callRealMethod();
        });
    }

    @Test
    void eliminaArchivosYCarpetaTrasUnAnalisisCorrecto() {
        assertThat(analizador.analizar(archivos).archivosAnalizados()).containsExactly("Unidad.java");
        assertThat(trabajo.get()).doesNotExist();
        verify(ejecutor).ejecutar(any(), any(), any());
    }

    @Test
    void reintentaCuandoLaCarpetaQuedaBloqueadaTemporalmente() {
        try (MockedStatic<Files> sistema = bloquearCarpeta(1)) {
            assertThat(analizador.analizar(archivos).versionSemgrep()).isEqualTo("simulada");
        }
        assertThat(intentos.get()).isEqualTo(2);
        assertThat(trabajo.get()).doesNotExist();
        verify(ejecutor, times(1)).ejecutar(any(), any(), any());
    }

    @Test
    void informaLimpiezaFallidaSiElBloqueoPersiste() {
        try (MockedStatic<Files> sistema = bloquearCarpeta(Integer.MAX_VALUE)) {
            assertThatThrownBy(() -> analizador.analizar(archivos))
                    .isInstanceOfSatisfying(ExcepcionAnalisisEstatico.class,
                            error -> assertThat(error.motivo()).isEqualTo(Motivo.LIMPIEZA_FALLIDA))
                    .hasCauseInstanceOf(AccessDeniedException.class);
        }
        assertThat(intentos.get()).isEqualTo(4);
    }

    @Test
    void conservaElErrorOriginalAunqueTambienFalleLaLimpieza() {
        ExcepcionAnalisisEstatico original = new ExcepcionAnalisisEstatico("Tiempo agotado", Motivo.TIEMPO_AGOTADO);
        doAnswer(invocacion -> {
            trabajo.set(invocacion.getArgument(0));
            throw original;
        }).when(ejecutor).ejecutar(any(), any(), any());
        try (MockedStatic<Files> sistema = bloquearCarpeta(Integer.MAX_VALUE)) {
            assertThatThrownBy(() -> analizador.analizar(archivos)).isSameAs(original);
        }
        assertThat(original.getSuppressed()).hasSize(1);
        assertThat(original.getSuppressed()[0]).isInstanceOf(AccessDeniedException.class);
    }
}
