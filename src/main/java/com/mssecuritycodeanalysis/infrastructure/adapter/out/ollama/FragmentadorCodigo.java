package com.mssecuritycodeanalysis.infrastructure.adapter.out.ollama;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisIA;
import com.mssecuritycodeanalysis.application.service.excepcion.ExcepcionAnalisisIA.Motivo;
import com.mssecuritycodeanalysis.domain.Constantes;
import com.mssecuritycodeanalysis.domain.model.ArchivoFuente;
import com.mssecuritycodeanalysis.infrastructure.config.PropiedadesOllama;

public class FragmentadorCodigo {

    private final PropiedadesOllama propiedades;
    private final ConstructorPromptIA constructorPrompt;

    public FragmentadorCodigo(PropiedadesOllama propiedades, ConstructorPromptIA constructorPrompt) {
        this.propiedades = propiedades;
        this.constructorPrompt = constructorPrompt;
    }

    public List<FragmentoCodigo> fragmentar(ArchivoFuente archivo) {
        if (archivo.contenido().isBlank()) {
            return List.of();
        }
        List<String> lineas = archivo.contenido().lines().toList();
        List<FragmentoCodigo> fragmentos = new ArrayList<>();
        int inicio = 0;
        while (inicio < lineas.size()) {
            if (fragmentos.size() >= propiedades.maxFragmentosPorArchivo()) {
                throw new ExcepcionAnalisisIA(Constantes.MENSAJE_LIMITE_FRAGMENTOS_IA, Motivo.FRAGMENTACION_INVALIDA);
            }
            FragmentoCodigo fragmento = crearFragmento(archivo, lineas, inicio);
            fragmentos.add(fragmento);
            if (fragmento.lineaFin() == lineas.size()) {
                break;
            }
            int cantidadLineas = fragmento.lineaFin() - inicio;
            int solapamiento = Math.min(propiedades.lineasSolapamiento(), cantidadLineas / 2);
            inicio = fragmento.lineaFin() - solapamiento;
        }
        return List.copyOf(fragmentos);
    }

    private FragmentoCodigo crearFragmento(ArchivoFuente archivo, List<String> lineas, int inicio) {
        StringBuilder codigo = new StringBuilder();
        int fin = inicio;
        while (fin < lineas.size() && fin - inicio < propiedades.maxLineasFragmento()) {
            String numerada = String.format(Locale.ROOT, Constantes.FORMATO_LINEA_NUMERADA, fin + 1, lineas.get(fin));
            if (numerada.length() > propiedades.maxCaracteresFragmento() - codigo.length()) {
                break;
            }
            int longitudAnterior = codigo.length();
            codigo.append(numerada);
            FragmentoCodigo candidato = new FragmentoCodigo(archivo.rutaRelativa(), archivo.lenguaje(),
                    inicio + 1, fin + 1, codigo.toString());
            if (!constructorPrompt.cabeEnContexto(candidato)) {
                codigo.setLength(longitudAnterior);
                break;
            }
            fin++;
        }
        if (fin == inicio) {
            throw new ExcepcionAnalisisIA(Constantes.MENSAJE_LINEA_IA_EXCESIVA, Motivo.FRAGMENTACION_INVALIDA);
        }
        return new FragmentoCodigo(archivo.rutaRelativa(), archivo.lenguaje(), inicio + 1, fin, codigo.toString());
    }
}
