package com.mssecuritycodeanalysis.infrastructure.adapter.out.semgrep;

import java.io.IOException;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisEstatico;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisEstatico.Motivo;
import com.mssecuritycodeanalysis.domain.Constantes;
import com.mssecuritycodeanalysis.domain.model.HallazgoSeguridad;
import com.mssecuritycodeanalysis.infrastructure.adapter.out.semgrep.EjecutorSemgrep.SalidaSemgrep;

public class InterpreteResultadoSemgrep {

    private static final Pattern PATRON_CWE = Pattern.compile(Constantes.PATRON_IDENTIFICADOR_CWE);

    private final ObjectReader lector;

    public InterpreteResultadoSemgrep(ObjectMapper objectMapper) {
        this.lector = objectMapper.reader().with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    }

    public LecturaSemgrep interpretar(SalidaSemgrep salida, Path directorioTrabajo, Path directorioFuentes,
            Set<String> rutasPermitidas, Set<String> reglasPermitidas) {
        try {
            ContextoRutas rutas = new ContextoRutas(directorioTrabajo, directorioFuentes,
                    salida.directorioAnalizador(), rutasPermitidas);
            JsonNode documento = lector.readTree(salida.contenido());
            validarDocumento(documento);
            List<String> archivosAnalizados = leerArchivosAnalizados(documento, rutas);
            List<HallazgoSeguridad> hallazgos = new ArrayList<>();
            for (JsonNode resultado : documento.get(Constantes.CAMPO_RESULTADOS_SEMGREP)) {
                hallazgos.add(leerHallazgo(resultado, rutas, reglasPermitidas));
            }
            return new LecturaSemgrep(List.copyOf(hallazgos), archivosAnalizados,
                    leerTexto(documento, Constantes.CAMPO_VERSION_SEMGREP));
        } catch (IOException | InvalidPathException excepcion) {
            throw salidaInvalida();
        }
    }

    private void validarDocumento(JsonNode documento) {
        if (documento == null || !documento.isObject()) {
            throw salidaInvalida();
        }
        validarArreglo(documento.get(Constantes.CAMPO_RESULTADOS_SEMGREP));
        JsonNode errores = documento.get(Constantes.CAMPO_ERRORES_SEMGREP);
        validarArreglo(errores);
        if (!errores.isEmpty()) {
            throw new ExcepcionAnalisisEstatico(Constantes.MENSAJE_EJECUCION_SEMGREP_FALLIDA,
                    Motivo.EJECUCION_FALLIDA);
        }
        JsonNode reglasOmitidas = documento.get(Constantes.CAMPO_REGLAS_OMITIDAS);
        if (reglasOmitidas != null && (!reglasOmitidas.isArray() || !reglasOmitidas.isEmpty())) {
            throw salidaInvalida();
        }
    }

    private List<String> leerArchivosAnalizados(JsonNode documento, ContextoRutas contexto) {
        JsonNode rutas = documento.path(Constantes.CAMPO_RUTAS_SEMGREP)
                .get(Constantes.CAMPO_ARCHIVOS_ESCANEADOS);
        validarArreglo(rutas);
        Set<String> archivos = new LinkedHashSet<>();
        for (JsonNode ruta : rutas) {
            if (!ruta.isTextual()) {
                throw salidaInvalida();
            }
            archivos.add(normalizarRuta(ruta.textValue(), contexto));
        }
        return archivos.stream().sorted().toList();
    }

    private HallazgoSeguridad leerHallazgo(JsonNode resultado, ContextoRutas contexto, Set<String> reglasPermitidas) {
        String identificador = leerTexto(resultado, Constantes.CAMPO_REGLA_HALLAZGO);
        if (!reglasPermitidas.contains(identificador)) {
            throw salidaInvalida();
        }
        String ruta = normalizarRuta(leerTexto(resultado, Constantes.CAMPO_RUTA_HALLAZGO), contexto);
        JsonNode inicio = resultado.path(Constantes.CAMPO_INICIO_HALLAZGO).get(Constantes.CAMPO_LINEA_HALLAZGO);
        if (inicio == null || !inicio.isIntegralNumber() || !inicio.canConvertToInt() || inicio.intValue() < 1) {
            throw salidaInvalida();
        }
        JsonNode extra = resultado.path(Constantes.CAMPO_EXTRA_HALLAZGO);
        String descripcion = leerTexto(extra, Constantes.CAMPO_MENSAJE_HALLAZGO);
        String riesgo = convertirRiesgo(leerTexto(extra, Constantes.CAMPO_SEVERIDAD_HALLAZGO));
        List<String> cwe = leerCwe(extra.path(Constantes.CAMPO_METADATA_HALLAZGO)
                .path(Constantes.CAMPO_CWE_HALLAZGO));
        return new HallazgoSeguridad(identificador, descripcion, cwe, ruta, inicio.intValue(),
                riesgo, Constantes.METODO_DETECCION_ESTATICO);
    }

    private String normalizarRuta(String ruta, ContextoRutas contexto) {
        String rutaNormalizada = ruta.replace(Constantes.CARACTER_SEPARADOR_WINDOWS,
                Constantes.CARACTER_SEPARADOR_UNIX);
        String prefijoAnalizador = contexto.directorioAnalizador()
                .replace(Constantes.CARACTER_SEPARADOR_WINDOWS, Constantes.CARACTER_SEPARADOR_UNIX)
                + Constantes.SEPARADOR_RUTA_UNIX;
        if (rutaNormalizada.startsWith(prefijoAnalizador)) {
            rutaNormalizada = rutaNormalizada.substring(prefijoAnalizador.length());
        }
        Path recibida = Path.of(rutaNormalizada);
        Path absoluta = recibida.isAbsolute()
                ? recibida.normalize() : contexto.directorioTrabajo().resolve(recibida).normalize();
        if (!absoluta.startsWith(contexto.directorioFuentes()) && !recibida.isAbsolute()) {
            absoluta = contexto.directorioFuentes().resolve(recibida).normalize();
        }
        if (!absoluta.startsWith(contexto.directorioFuentes())) {
            throw salidaInvalida();
        }
        String relativa = contexto.directorioFuentes().relativize(absoluta).toString()
                .replace(Constantes.CARACTER_SEPARADOR_WINDOWS, Constantes.CARACTER_SEPARADOR_UNIX);
        if (!contexto.rutasPermitidas().contains(relativa)) {
            throw salidaInvalida();
        }
        return relativa;
    }

    private List<String> leerCwe(JsonNode valor) {
        Set<String> identificadores = new LinkedHashSet<>();
        if (valor.isMissingNode() || valor.isNull()) {
            return List.of();
        }
        if (valor.isTextual()) {
            agregarCwe(valor.textValue(), identificadores);
        } else if (valor.isArray()) {
            for (JsonNode elemento : valor) {
                if (!elemento.isTextual()) {
                    throw salidaInvalida();
                }
                agregarCwe(elemento.textValue(), identificadores);
            }
        } else {
            throw salidaInvalida();
        }
        return List.copyOf(identificadores);
    }

    private void agregarCwe(String texto, Set<String> identificadores) {
        Matcher coincidencias = PATRON_CWE.matcher(texto);
        while (coincidencias.find()) {
            identificadores.add(coincidencias.group());
        }
    }

    private String convertirRiesgo(String severidad) {
        return switch (severidad) {
            case Constantes.SEVERIDAD_CRITICAL -> Constantes.RIESGO_CRITICO;
            case Constantes.SEVERIDAD_ERROR, Constantes.SEVERIDAD_HIGH -> Constantes.RIESGO_ALTO;
            case Constantes.SEVERIDAD_WARNING, Constantes.SEVERIDAD_MEDIUM -> Constantes.RIESGO_MEDIO;
            case Constantes.SEVERIDAD_INFO, Constantes.SEVERIDAD_LOW -> Constantes.RIESGO_BAJO;
            default -> throw salidaInvalida();
        };
    }

    private void validarArreglo(JsonNode nodo) {
        if (nodo == null || !nodo.isArray()) {
            throw salidaInvalida();
        }
    }

    private String leerTexto(JsonNode objeto, String campo) {
        JsonNode valor = objeto.get(campo);
        if (valor == null || !valor.isTextual() || valor.textValue().isBlank()) {
            throw salidaInvalida();
        }
        return valor.textValue();
    }

    private ExcepcionAnalisisEstatico salidaInvalida() {
        return new ExcepcionAnalisisEstatico(Constantes.MENSAJE_SALIDA_SEMGREP_INVALIDA, Motivo.SALIDA_INVALIDA);
    }

    public record LecturaSemgrep(List<HallazgoSeguridad> hallazgos, List<String> archivosAnalizados,
            String versionSemgrep) {
    }

    private record ContextoRutas(Path directorioTrabajo, Path directorioFuentes,
            String directorioAnalizador, Set<String> rutasPermitidas) {
    }
}
