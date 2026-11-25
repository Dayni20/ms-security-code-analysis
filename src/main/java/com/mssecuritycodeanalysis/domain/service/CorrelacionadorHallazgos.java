package com.mssecuritycodeanalysis.domain.service;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.mssecuritycodeanalysis.domain.Constantes;
import com.mssecuritycodeanalysis.domain.model.ArchivoFuente;
import com.mssecuritycodeanalysis.domain.model.HallazgoHibrido;
import com.mssecuritycodeanalysis.domain.model.HallazgoHibrido.EstadoCorrelacion;
import com.mssecuritycodeanalysis.domain.model.HallazgoHibrido.Procedencia;
import com.mssecuritycodeanalysis.domain.model.HallazgoSeguridad;
import com.mssecuritycodeanalysis.domain.service.EvaluadorEvidenciaCodigo.Ubicacion;

public class CorrelacionadorHallazgos {

    public List<HallazgoHibrido> correlacionar(List<ArchivoFuente> archivos, List<HallazgoSeguridad> estaticos,
            List<HallazgoSeguridad> ia, Set<String> archivosComparables) {
        Map<String, EvaluadorEvidenciaCodigo> evaluadores = new LinkedHashMap<>();
        Map<Clave, List<Deteccion>> grupos = new LinkedHashMap<>();
        List<HallazgoSeguridad> todos = new ArrayList<>(estaticos);
        todos.addAll(ia);
        Map<String, ArchivoFuente> fuentes = new LinkedHashMap<>();
        archivos.forEach(archivo -> fuentes.put(normalizarRuta(archivo.rutaRelativa()), archivo));
        for (int indice = 0; indice < todos.size(); indice++) {
            HallazgoSeguridad hallazgo = todos.get(indice);
            Procedencia procedencia = indice < estaticos.size() ? Procedencia.ESTATICO : Procedencia.IA;
            String ruta = normalizarRuta(hallazgo.rutaRelativa());
            ArchivoFuente archivo = fuentes.get(ruta);
            EvaluadorEvidenciaCodigo evaluador = archivo == null ? null
                    : evaluadores.computeIfAbsent(ruta, ignorada -> new EvaluadorEvidenciaCodigo(archivo));
            List<String> categorias = hallazgo.cwe().isEmpty() ? List.of(Constantes.CADENA_VACIA) : hallazgo.cwe().stream().distinct().toList();
            for (String cwe : categorias) {
                Ubicacion ubicacion = evaluador == null ? pendiente(hallazgo.linea()) : evaluador.localizar(cwe, hallazgo.linea());
                HallazgoSeguridad identidad = ubicacion.operacion() == null
                        ? new HallazgoSeguridad(hallazgo.identificadorRegla(), hallazgo.descripcion(), List.of(cwe), ruta,
                                hallazgo.linea(), hallazgo.nivelRiesgo(), procedencia.name()) : null;
                Clave clave = new Clave(ruta, cwe, ubicacion.operacion(), identidad);
                grupos.computeIfAbsent(clave, ignorada -> new ArrayList<>()).add(new Deteccion(hallazgo, procedencia, ubicacion));
            }
        }
        List<HallazgoHibrido> resultado = new ArrayList<>();
        grupos.entrySet().stream().sorted(Comparator.comparing((Map.Entry<Clave, List<Deteccion>> entrada) -> entrada.getKey().ruta())
                .thenComparing(entrada -> entrada.getKey().cwe())
                .thenComparingInt(entrada -> entrada.getValue().getFirst().ubicacion().lineaOperacion()))
                .forEach(entrada -> resultado.add(consolidar(entrada.getKey(), entrada.getValue(), archivosComparables, resultado.size() + 1)));
        return List.copyOf(resultado);
    }

    private HallazgoHibrido consolidar(Clave clave, List<Deteccion> grupo, Set<String> comparables, int numero) {
        Set<Procedencia> procedencias = grupo.stream().map(Deteccion::procedencia).collect(java.util.stream.Collectors.toSet());
        Procedencia procedencia = procedencias.size() == 2 ? Procedencia.AMBOS : grupo.getFirst().procedencia();
        Ubicacion ubicacion = grupo.getFirst().ubicacion();
        EstadoCorrelacion correlacion;
        if (procedencia == Procedencia.AMBOS) correlacion = EstadoCorrelacion.MISMA_OPERACION;
        else if (ubicacion.ambigua()) correlacion = EstadoCorrelacion.AMBIGUA;
        else if (!comparables.contains(clave.ruta())) correlacion = EstadoCorrelacion.NO_COMPARABLE;
        else correlacion = procedencia == Procedencia.ESTATICO ? EstadoCorrelacion.SOLO_ESTATICO : EstadoCorrelacion.SOLO_IA;
        HallazgoSeguridad principal = grupo.stream().map(Deteccion::hallazgo)
                .min(Comparator.comparingInt(hallazgo -> riesgo(hallazgo.nivelRiesgo()))).orElseThrow();
        return new HallazgoHibrido(Constantes.PREFIJO_HALLAZGO_HIBRIDO + numero, clave.ruta(), clave.cwe(),
                ubicacion.lineaOperacion(), principal.descripcion(), principal.nivelRiesgo(), procedencia, correlacion,
                ubicacion.estado(), ubicacion.justificacion(), ubicacion.evidencia(),
                grupo.stream().map(Deteccion::hallazgo).distinct().toList());
    }

    private int riesgo(String nivel) {
        int indice = Constantes.NIVELES_RIESGO_IA.indexOf(nivel);
        return indice < 0 ? Integer.MAX_VALUE : indice;
    }

    private Ubicacion pendiente(int linea) {
        return new Ubicacion(null, linea, HallazgoHibrido.EstadoRevision.PENDIENTE_REVISION,
                Constantes.EVIDENCIA_PENDIENTE, List.of(), false);
    }

    public static String normalizarRuta(String ruta) {
        if (ruta == null) return Constantes.CADENA_VACIA;
        String reemplazada = ruta.replace('\\', '/');
        if (reemplazada.startsWith(Constantes.SEPARADOR_RUTA_UNIX) || reemplazada.indexOf(':') >= 0) return reemplazada;
        Deque<String> segmentos = new ArrayDeque<>();
        for (String segmento : reemplazada.split(Constantes.SEPARADOR_RUTA_UNIX)) {
            if (segmento.isEmpty() || segmento.equals(Constantes.SEGMENTO_ACTUAL)) continue;
            if (segmento.equals(Constantes.SEGMENTO_PADRE)) {
                if (segmentos.isEmpty()) return reemplazada;
                segmentos.removeLast();
            } else segmentos.addLast(segmento);
        }
        return String.join(Constantes.SEPARADOR_RUTA_UNIX, segmentos);
    }

    private record Clave(String ruta, String cwe, Integer operacion, HallazgoSeguridad identidad) {
    }
    private record Deteccion(HallazgoSeguridad hallazgo, Procedencia procedencia, Ubicacion ubicacion) {
    }
}
