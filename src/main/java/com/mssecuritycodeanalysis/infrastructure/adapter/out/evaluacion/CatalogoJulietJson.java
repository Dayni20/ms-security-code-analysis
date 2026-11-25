package com.mssecuritycodeanalysis.infrastructure.adapter.out.evaluacion;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.zip.ZipFile;
import java.util.zip.ZipEntry;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mssecuritycodeanalysis.application.port.out.CatalogoCasosExperimentales;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionEvaluacion;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionEvaluacion.Motivo;
import com.mssecuritycodeanalysis.domain.model.evaluacion.CasoExperimental;
import com.mssecuritycodeanalysis.domain.service.EvaluadorCasoExperimental;

public class CatalogoJulietJson implements CatalogoCasosExperimentales {
    private final Path raiz;
    private final Path referencia;
    private final ObjectMapper mapper;
    public CatalogoJulietJson(Path raiz, Path referencia, ObjectMapper mapper) {
        this.raiz = raiz.toAbsolutePath().normalize();
        this.referencia = referencia;
        this.mapper = mapper;
    }
    @Override
    public Catalogo cargar() {
        try {
            Path archivo = resolver(referencia.toString());
            byte[] contenido = Files.readAllBytes(archivo);
            JsonNode registro = mapper.readTree(contenido);
            exigir(registro != null && registro.isObject(), "El registro no es un objeto JSON");
            exigir(registro.path("casos").isArray() && !registro.path("casos").isEmpty(), "El registro no contiene casos");
            List<CasoExperimental> casos = new ArrayList<>();
            Set<String> identificadores = new HashSet<>();
            for (JsonNode nodo : registro.path("casos")) {
                CasoExperimental caso = leerCaso(nodo);
                exigir(identificadores.add(caso.identificador()), "Identificador duplicado: " + caso.identificador());
                casos.add(caso);
            }
            return new Catalogo(casos, Map.of("sha256Catalogo", huella(contenido),
                    "dataset", texto(registro, "dataset"),
                    "sha256DistribucionOficial", texto(registro, "sha256DistribucionOficial"),
                    "sha256ManifestOriginal", texto(registro, "sha256ManifestOriginal")));
        } catch (IOException | IllegalArgumentException excepcion) {
            throw new ExcepcionEvaluacion(Motivo.CATALOGO_INVALIDO, "No se pudo validar el catalogo experimental", excepcion);
        }
    }
    private CasoExperimental leerCaso(JsonNode nodo) throws IOException {
        String id = texto(nodo, "identificador");
        exigir(id.matches("[A-Za-z][A-Za-z0-9_-]{0,79}"), "Identificador no valido");
        String original = texto(nodo, "cweOriginal");
        exigir(Set.of("CWE-89", "CWE-78", "CWE-23", "CWE-36").contains(original), "CWE original no admitido");
        String normalizado = texto(nodo, "cweNormalizado");
        exigir(normalizado.equals(EvaluadorCasoExperimental.normalizarCwe(original)), "Normalizacion CWE inconsistente");
        CasoExperimental.ClasificacionEsperada clasificacion = CasoExperimental.ClasificacionEsperada.valueOf(texto(nodo, "clasificacionEsperada"));
        Path preparado = resolver(texto(nodo, "archivoPreparado"));
        Path paquete = resolver(texto(nodo, "paqueteAnalisis"));
        exigir(paquete.getFileName().toString().endsWith(".zip"), "Paquete sin extension ZIP");
        Path directorioCaso = paquete.resolveSibling(paquete.getFileName().toString().replaceFirst("\\.zip$", ""));
        exigir(preparado.startsWith(directorioCaso), "Fuente fuera del caso");
        comprobarHuella(preparado, texto(nodo, "sha256Preparado"));
        Path fuenteOriginal = resolver(texto(nodo, "archivoOriginal"));
        comprobarHuella(fuenteOriginal, texto(nodo, "sha256Original"));
        int lineasOriginales = Files.readAllLines(fuenteOriginal).size();
        List<CasoExperimental.Correspondencia> correspondencia = new ArrayList<>();
        Set<Integer> preparadas = new HashSet<>();
        int lineas = Files.readAllLines(preparado).size();
        for (JsonNode par : nodo.path("correspondenciaLineas")) {
            int origen = par.path("original").asInt();
            int destino = par.path("preparada").asInt();
            exigir(origen > 0 && origen <= lineasOriginales && destino > 0 && destino <= lineas && preparadas.add(destino), "Correspondencia de lineas no valida");
            correspondencia.add(new CasoExperimental.Correspondencia(origen, destino));
        }
        exigir(preparadas.size() == lineas, "Correspondencia incompleta");
        List<Integer> referencias = enteros(nodo, "lineasVulnerabilidadPreparadas", lineas);
        List<Integer> operaciones = enteros(nodo, "lineasOperacionVulnerablePreparadas", lineas);
        validarCorrespondencias(nodo, correspondencia, "lineasVulnerabilidadOriginales", referencias);
        validarCorrespondencias(nodo, correspondencia, "lineasOperacionVulnerableOriginales", operaciones);
        validarCorrespondencias(nodo, correspondencia, "lineasOperacionSensibleOriginales",
                enteros(nodo, "lineasOperacionSensiblePreparadas", lineas));
        if (clasificacion == CasoExperimental.ClasificacionEsperada.VULNERABLE) {
            exigir(!referencias.isEmpty() && !operaciones.isEmpty() && !nodo.path("anotacionesManifiesto").isEmpty(), "Caso vulnerable sin ubicaciones verificables");
            Set<Integer> anotadas = new HashSet<>();
            for (JsonNode anotacion : nodo.path("anotacionesManifiesto")) anotadas.add(anotacion.path("line").asInt());
            for (int linea : referencias) {
                exigir(correspondencia.stream().anyMatch(par -> par.preparada() == linea && anotadas.contains(par.original())),
                        "Referencia sin anotacion de manifiesto");
            }
        } else {
            exigir(referencias.isEmpty() && operaciones.isEmpty(), "Caso seguro con referencias vulnerables");
        }
        Map<String, String> permitidos = new HashMap<>();
        String ruta = relativa(directorioCaso.relativize(preparado));
        permitidos.put(ruta, texto(nodo, "sha256Preparado"));
        for (JsonNode dependencia : nodo.path("dependencias")) {
            Path archivo = resolver(texto(dependencia, "archivoPreparado"));
            String hash = texto(dependencia, "sha256Preparado");
            comprobarHuella(archivo, hash);
            String entrada = archivo.startsWith(directorioCaso) ? relativa(directorioCaso.relativize(archivo))
                    : "lib/" + archivo.getFileName();
            exigir(permitidos.putIfAbsent(entrada, hash) == null, "Dependencia duplicada");
        }
        comprobarPaquete(paquete, texto(nodo, "sha256PaqueteAnalisis"), permitidos);
        return new CasoExperimental(id, texto(nodo, "archivoOriginal"), texto(nodo, "archivoPreparado"),
                texto(nodo, "paqueteAnalisis"), ruta, texto(nodo, "metodoOriginal"), original, normalizado,
                clasificacion, referencias, operaciones, correspondencia, texto(nodo, "sha256Original"),
                texto(nodo, "sha256Preparado"), texto(nodo, "sha256PaqueteAnalisis"),
                texto(nodo, "grupoOrigen"), permitidos);
    }
    @Override
    public InputStream abrir(CasoExperimental caso) {
        try {
            Path archivo = resolver(caso.paqueteAnalisis());
            comprobarPaquete(archivo, caso.sha256PaqueteAnalisis(), caso.archivosPermitidos());
            return Files.newInputStream(archivo);
        } catch (IOException excepcion) {
            throw new ExcepcionEvaluacion(Motivo.CATALOGO_INVALIDO, "No se pudo abrir el caso " + caso.identificador(), excepcion);
        }
    }
    private void comprobarPaquete(Path archivo, String hash, Map<String, String> permitidos) throws IOException {
        comprobarHuella(archivo, hash);
        Set<String> encontrados = new HashSet<>();
        try (ZipFile zip = new ZipFile(archivo.toFile())) {
            Enumeration<? extends ZipEntry> entradas = zip.entries();
            while (entradas.hasMoreElements()) {
                ZipEntry entrada = entradas.nextElement();
                if (entrada.isDirectory()) continue;
                String nombre = entrada.getName();
                exigir(permitidos.containsKey(nombre) && encontrados.add(nombre), "Contenido inesperado en ZIP: " + nombre);
                try (InputStream flujo = zip.getInputStream(entrada)) {
                    byte[] bytes = flujo.readNBytes(5 * 1024 * 1024 + 1);
                    exigir(bytes.length <= 5 * 1024 * 1024 && huella(bytes).equals(permitidos.get(nombre)), "Contenido ZIP alterado");
                }
            }
        }
        exigir(encontrados.equals(permitidos.keySet()), "ZIP incompleto");
    }
    private void validarCorrespondencias(JsonNode nodo, List<CasoExperimental.Correspondencia> mapa,
            String campoOriginal, List<Integer> preparadas) {
        JsonNode originales = nodo.path(campoOriginal);
        exigir(originales.isArray() && originales.size() == preparadas.size(), "Referencias inconsistentes");
        for (int indice = 0; indice < preparadas.size(); indice++) {
            int original = originales.get(indice).asInt();
            int preparada = preparadas.get(indice);
            exigir(mapa.contains(new CasoExperimental.Correspondencia(original, preparada)), "Referencia no corresponde al original");
        }
    }
    private List<Integer> enteros(JsonNode nodo, String campo, int maximo) {
        JsonNode lista = nodo.path(campo);
        exigir(lista.isArray(), "Lista de ubicaciones ausente: " + campo);
        List<Integer> valores = new ArrayList<>();
        for (JsonNode valor : lista) {
            exigir(valor.isIntegralNumber() && valor.asInt() > 0 && valor.asInt() <= maximo, "Ubicacion fuera de la fuente");
            valores.add(valor.asInt());
        }
        return valores;
    }
    private Path resolver(String ruta) throws IOException {
        Path relativa = Path.of(ruta);
        exigir(!relativa.isAbsolute(), "Se requiere ruta relativa");
        Path destino = raiz.resolve(relativa).normalize();
        exigir(destino.startsWith(raiz), "Ruta fuera del proyecto: " + ruta);
        exigir(Files.isRegularFile(destino), "Archivo inexistente: " + ruta + " (raiz experimental: " + raiz + ")");
        exigir(destino.toRealPath().startsWith(raiz.toRealPath()), "Enlace fuera del proyecto");
        return destino;
    }
    private void comprobarHuella(Path archivo, String esperada) throws IOException {
        exigir(esperada.matches("[a-f0-9]{64}"), "Huella SHA-256 no valida");
        try (InputStream flujo = Files.newInputStream(archivo)) {
            MessageDigest digest = digest();
            byte[] buffer = new byte[8192];
            int cantidad;
            while ((cantidad = flujo.read(buffer)) != -1) digest.update(buffer, 0, cantidad);
            exigir(HexFormat.of().formatHex(digest.digest()).equals(esperada), "Huella incorrecta: " + raiz.relativize(archivo));
        }
    }
    private String texto(JsonNode nodo, String campo) {
        JsonNode valor = nodo.path(campo);
        exigir(valor.isTextual() && !valor.asText().isBlank(), "Campo obligatorio: " + campo);
        return valor.asText();
    }
    private String relativa(Path ruta) { return ruta.toString().replace('\\', '/'); }
    private String huella(byte[] bytes) { return HexFormat.of().formatHex(digest().digest(bytes)); }
    private MessageDigest digest() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException imposible) { throw new IllegalStateException(imposible); }
    }
    private void exigir(boolean condicion, String mensaje) {
        if (!condicion) throw new ExcepcionEvaluacion(Motivo.CATALOGO_INVALIDO, mensaje);
    }
}
