package com.mssecuritycodeanalysis.infrastructure.adapter.out.ollama;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.databind.JsonNode;
import com.mssecuritycodeanalysis.application.port.out.AnalizadorIA;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisIA;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisIA.Motivo;
import com.mssecuritycodeanalysis.domain.Constantes;
import com.mssecuritycodeanalysis.domain.model.ArchivoFuente;
import com.mssecuritycodeanalysis.domain.model.HallazgoSeguridad;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisIA;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisIA.DetalleFragmento;
import com.mssecuritycodeanalysis.domain.model.ResultadoAnalisisIA.ParametrosGeneracion;
import com.mssecuritycodeanalysis.infrastructure.adapter.out.ollama.ClienteOllama.IdentidadModelo;
import com.mssecuritycodeanalysis.infrastructure.config.PropiedadesOllama;

public class AnalizadorOllama implements AnalizadorIA {

    private final PropiedadesOllama propiedades;
    private final ClienteOllama cliente;
    private final ConstructorPromptIA constructorPrompt;
    private final FragmentadorCodigo fragmentador;
    private final InterpreteRespuestaIA interprete;

    public AnalizadorOllama(PropiedadesOllama propiedades, ClienteOllama cliente,
            ConstructorPromptIA constructorPrompt, FragmentadorCodigo fragmentador, InterpreteRespuestaIA interprete) {
        this.propiedades = propiedades;
        this.cliente = cliente;
        this.constructorPrompt = constructorPrompt;
        this.fragmentador = fragmentador;
        this.interprete = interprete;
    }

    @Override
    public ResultadoAnalisisIA analizar(List<ArchivoFuente> archivos) {
        Map<ClaveHallazgo, HallazgoSeguridad> hallazgos = new LinkedHashMap<>();
        List<DetalleFragmento> detalles = new ArrayList<>();
        Set<String> completados = new LinkedHashSet<>();
        IdentidadModelo identidad = identificarModelo(archivos, detalles, completados, hallazgos);
        for (int indice = 0; indice < archivos.size(); indice++) {
            ArchivoFuente archivo = archivos.get(indice);
            if (!tieneCobertura(archivo)) {
                detalles.add(detalleArchivo(archivo, Constantes.ESTADO_SIN_COBERTURA,
                        Motivo.SIN_COBERTURA.name(), Constantes.MENSAJE_SIN_COBERTURA_IA));
                continue;
            }
            try {
                analizarArchivo(archivo, detalles, hallazgos);
                completados.add(archivo.rutaRelativa());
            } catch (ExcepcionAnalisisIA excepcion) {
                registrarPendientes(archivos.subList(indice + 1, archivos.size()), detalles,
                        Constantes.ESTADO_FRAGMENTO_PENDIENTE, excepcion.motivo().name(),
                        Constantes.MENSAJE_FRAGMENTO_PENDIENTE);
                ResultadoAnalisisIA parcial = crearResultado(archivos, identidad, hallazgos, completados, detalles);
                throw new ExcepcionAnalisisIA(excepcion.getMessage(), excepcion.motivo(), excepcion, parcial);
            }
        }
        ResultadoAnalisisIA resultado = crearResultado(archivos, identidad, hallazgos, completados, detalles);
        if (!resultado.lenguajesSinCobertura().isEmpty()) {
            throw new ExcepcionAnalisisIA(Constantes.MENSAJE_SIN_COBERTURA_IA, Motivo.SIN_COBERTURA, null, resultado);
        }
        return resultado;
    }

    private IdentidadModelo identificarModelo(List<ArchivoFuente> archivos, List<DetalleFragmento> detalles,
            Set<String> completados, Map<ClaveHallazgo, HallazgoSeguridad> hallazgos) {
        if (archivos.stream().noneMatch(this::tieneCobertura)) {
            registrarPendientes(archivos, detalles, Constantes.ESTADO_SIN_COBERTURA,
                    Motivo.SIN_COBERTURA.name(), Constantes.MENSAJE_SIN_COBERTURA_IA);
            ResultadoAnalisisIA parcial = crearResultado(archivos, null, hallazgos, completados, detalles);
            throw new ExcepcionAnalisisIA(Constantes.MENSAJE_SIN_COBERTURA_IA, Motivo.SIN_COBERTURA, null, parcial);
        }
        try {
            return cliente.identificarModelo();
        } catch (ExcepcionAnalisisIA excepcion) {
            registrarPendientes(archivos, detalles, Constantes.ESTADO_FRAGMENTO_PENDIENTE,
                    excepcion.motivo().name(), excepcion.getMessage());
            ResultadoAnalisisIA parcial = crearResultado(archivos, null, hallazgos, completados, detalles);
            throw new ExcepcionAnalisisIA(excepcion.getMessage(), excepcion.motivo(), excepcion, parcial);
        }
    }

    private void analizarArchivo(ArchivoFuente archivo, List<DetalleFragmento> detalles,
            Map<ClaveHallazgo, HallazgoSeguridad> hallazgos) {
        List<FragmentoCodigo> fragmentos;
        try {
            fragmentos = fragmentador.fragmentar(archivo);
        } catch (ExcepcionAnalisisIA excepcion) {
            detalles.add(detalleArchivo(archivo, Constantes.ESTADO_FRAGMENTO_FALLIDO,
                    excepcion.motivo().name(), excepcion.getMessage()));
            throw excepcion;
        }
        for (int indice = 0; indice < fragmentos.size(); indice++) {
            FragmentoCodigo fragmento = fragmentos.get(indice);
            String huella = constructorPrompt.huellaSolicitud(fragmento);
            try {
                JsonNode respuesta = cliente.generar(constructorPrompt.crearPeticion(fragmento));
                int presupuestoEntrada = propiedades.contexto() - propiedades.maxTokensGeneracion();
                List<HallazgoSeguridad> encontrados = interprete.interpretar(respuesta, fragmento,
                        propiedades.modelo(), presupuestoEntrada);
                agregarHallazgos(encontrados, hallazgos);
                detalles.add(new DetalleFragmento(archivo.rutaRelativa(), fragmento.lineaInicio(), fragmento.lineaFin(),
                        Constantes.ESTADO_FRAGMENTO_ANALIZADO, null, null, huella));
            } catch (ExcepcionAnalisisIA excepcion) {
                detalles.add(new DetalleFragmento(archivo.rutaRelativa(), fragmento.lineaInicio(), fragmento.lineaFin(),
                        Constantes.ESTADO_FRAGMENTO_FALLIDO, excepcion.motivo().name(), excepcion.getMessage(), huella));
                registrarFragmentosPendientes(fragmentos.subList(indice + 1, fragmentos.size()), detalles);
                throw excepcion;
            }
        }
    }

    private void agregarHallazgos(List<HallazgoSeguridad> encontrados, Map<ClaveHallazgo, HallazgoSeguridad> hallazgos) {
        for (HallazgoSeguridad hallazgo : encontrados) {
            ClaveHallazgo clave = new ClaveHallazgo(hallazgo.rutaRelativa(), hallazgo.linea(), hallazgo.cwe().getFirst());
            hallazgos.merge(clave, hallazgo, this::elegirMayorRiesgo);
        }
    }

    private HallazgoSeguridad elegirMayorRiesgo(HallazgoSeguridad anterior, HallazgoSeguridad nuevo) {
        int riesgoAnterior = Constantes.NIVELES_RIESGO_IA.indexOf(anterior.nivelRiesgo());
        int riesgoNuevo = Constantes.NIVELES_RIESGO_IA.indexOf(nuevo.nivelRiesgo());
        return riesgoNuevo < riesgoAnterior ? nuevo : anterior;
    }

    private void registrarFragmentosPendientes(List<FragmentoCodigo> fragmentos, List<DetalleFragmento> detalles) {
        for (FragmentoCodigo fragmento : fragmentos) {
            detalles.add(new DetalleFragmento(fragmento.rutaRelativa(), fragmento.lineaInicio(), fragmento.lineaFin(),
                    Constantes.ESTADO_FRAGMENTO_PENDIENTE, null, Constantes.MENSAJE_FRAGMENTO_PENDIENTE, null));
        }
    }

    private void registrarPendientes(List<ArchivoFuente> archivos, List<DetalleFragmento> detalles,
            String estado, String motivo, String descripcion) {
        for (ArchivoFuente archivo : archivos) {
            detalles.add(detalleArchivo(archivo, estado, motivo, descripcion));
        }
    }

    private DetalleFragmento detalleArchivo(ArchivoFuente archivo, String estado, String motivo, String descripcion) {
        int cantidadLineas = (int) archivo.contenido().lines().count();
        return new DetalleFragmento(archivo.rutaRelativa(), cantidadLineas == 0 ? 0 : 1,
                cantidadLineas, estado, motivo, descripcion, null);
    }

    private boolean tieneCobertura(ArchivoFuente archivo) {
        return propiedades.lenguajesAdmitidos().contains(archivo.lenguaje());
    }

    private ResultadoAnalisisIA crearResultado(List<ArchivoFuente> archivos, IdentidadModelo identidad,
            Map<ClaveHallazgo, HallazgoSeguridad> hallazgos, Set<String> completados, List<DetalleFragmento> detalles) {
        List<String> reconocidos = archivos.stream().map(ArchivoFuente::lenguaje).distinct().sorted().toList();
        List<String> cubiertos = reconocidos.stream().filter(propiedades.lenguajesAdmitidos()::contains).toList();
        List<String> sinCobertura = reconocidos.stream().filter(lenguaje -> !cubiertos.contains(lenguaje)).toList();
        boolean completo = sinCobertura.isEmpty() && completados.size() == archivos.size();
        ParametrosGeneracion parametros = new ParametrosGeneracion(propiedades.temperatura(), propiedades.contexto(),
                propiedades.maxTokensGeneracion(), propiedades.semilla(), propiedades.maxLineasFragmento(),
                propiedades.maxCaracteresFragmento(), propiedades.lineasSolapamiento(), propiedades.margenTokens(),
                propiedades.maxFragmentosPorArchivo());
        return new ResultadoAnalisisIA(completo ? Constantes.ESTADO_ANALISIS_COMPLETADO : Constantes.ESTADO_ANALISIS_INCOMPLETO,
                List.copyOf(hallazgos.values()), List.copyOf(completados), reconocidos, cubiertos, sinCobertura,
                propiedades.modelo(), identidad == null ? null : identidad.digest(), parametros,
                Constantes.VERSION_PROMPT_IA, constructorPrompt.huellaPrompt(), Constantes.METODO_DETECCION_IA,
                detalles, List.of(Constantes.LIMITACION_ANALISIS_IA, Constantes.LIMITACION_ESTIMACION_CONTEXTO,
                        Constantes.LIMITACION_HALLAZGOS_IA));
    }

    private record ClaveHallazgo(String rutaRelativa, int linea, String cwe) {
    }
}
