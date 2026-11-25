package com.mssecuritycodeanalysis.domain.service;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.mssecuritycodeanalysis.domain.Constantes;
import com.mssecuritycodeanalysis.domain.model.ArchivoFuente;
import com.mssecuritycodeanalysis.domain.model.HallazgoHibrido.EstadoRevision;
import com.mssecuritycodeanalysis.domain.model.HallazgoHibrido.Evidencia;
import com.mssecuritycodeanalysis.domain.model.HallazgoHibrido.TipoEvidencia;

public class EvaluadorEvidenciaCodigo {

    private final List<Token> tokens = new ArrayList<>();
    private final List<Declaracion> declaraciones = new ArrayList<>();
    private final List<Operacion> operaciones = new ArrayList<>();
    private final Map<Integer, Integer> padres = new HashMap<>();
    private final boolean java;

    public EvaluadorEvidenciaCodigo(ArchivoFuente archivo) {
        this.java = Constantes.LENGUAJE_EVIDENCIA_JAVA.equals(archivo.lenguaje());
        if (tokenizar(archivo.contenido())) {
            if (java) identificarDeclaraciones();
            identificarOperaciones();
        }
    }

    public Ubicacion localizar(String cwe, int linea) {
        List<Operacion> candidatas = operaciones.stream().filter(operacion -> operacion.cwe().equals(cwe))
                .filter(operacion -> contieneLinea(operacion.inicio(), operacion.fin(), linea)
                        || operacion.valor().declaraciones().stream()
                                .anyMatch(declaracion -> contieneLinea(declaracion.inicio(), declaracion.fin(), linea)))
                .toList();
        if (candidatas.size() != 1) {
            return new Ubicacion(null, linea, EstadoRevision.PENDIENTE_REVISION,
                    candidatas.isEmpty() ? Constantes.EVIDENCIA_PENDIENTE : Constantes.CORRELACION_AMBIGUA,
                    List.of(), candidatas.size() > 1);
        }
        Operacion operacion = candidatas.getFirst();
        List<Evidencia> evidencia = new ArrayList<>(operacion.valor().evidencia());
        evidencia.add(paso(TipoEvidencia.OPERACION, operacion.inicio(), operacion.fin(), Constantes.EVIDENCIA_OPERACION));
        EstadoRevision estado = EstadoRevision.PENDIENTE_REVISION;
        String justificacion = Constantes.EVIDENCIA_PENDIENTE;
        if (operacion.valor().tipo() == TipoValor.CONSTANTE) {
            estado = EstadoRevision.DESCARTADO_CON_JUSTIFICACION;
            justificacion = operacion.preparada() ? Constantes.EVIDENCIA_PREPARADA : Constantes.EVIDENCIA_CONSTANTE;
            evidencia.add(paso(TipoEvidencia.PROTECCION, operacion.inicio(), operacion.fin(), justificacion));
        } else if (operacion.constructorArchivo()) {
            justificacion = Constantes.EVIDENCIA_CONSTRUCTOR;
        } else if (operacion.valor().tipo() == TipoValor.EXTERNO && esFlujoLineal(operacion)) {
            estado = EstadoRevision.RESPALDADO_POR_EVIDENCIA;
            justificacion = Constantes.EVIDENCIA_FLUJO;
        }
        return new Ubicacion(operacion.inicio(), tokens.get(operacion.inicio()).linea(), estado,
                justificacion, List.copyOf(evidencia), false);
    }

    private boolean contieneLinea(int inicio, int fin, int linea) {
        return tokens.get(inicio).linea() <= linea && linea <= tokens.get(fin).linea();
    }

    private void identificarDeclaraciones() {
        for (int indice = 0; indice + 3 < tokens.size(); indice++) {
            if (!palabra(indice, Constantes.PALABRA_STRING) || !identificador(indice + 1) || !simbolo(indice + 2, '=')) {
                continue;
            }
            int fin = indice + 3;
            while (fin < tokens.size() && tokens.get(fin).bloque() == tokens.get(indice).bloque() && !simbolo(fin, ';')) {
                fin++;
            }
            if (fin < tokens.size() && simbolo(fin, ';')) {
                declaraciones.add(new Declaracion(tokens.get(indice + 1).texto(), indice, fin,
                        tokens.get(indice).bloque(), indice + 3, fin));
            }
        }
    }

    private void identificarOperaciones() {
        for (int indice = 0; indice + 1 < tokens.size(); indice++) {
            String metodo = tokens.get(indice).texto();
            if (!simbolo(indice + 1, '(')) {
                continue;
            }
            String cwe = null;
            int inicio = indice;
            boolean preparada = false;
            boolean constructor = false;
            if (!java) {
                if (Constantes.SQL_OTROS_LENGUAJES.contains(metodo)) cwe = Constantes.CWE_SQL;
                if (Constantes.COMANDOS_OTROS_LENGUAJES.contains(metodo)) cwe = Constantes.CWE_COMANDOS;
                if (Constantes.RUTAS_OTROS_LENGUAJES.contains(metodo)) cwe = Constantes.CWE_RUTAS;
                inicio = simbolo(indice - 1, '.') && identificador(indice - 2) ? indice - 2 : indice;
            } else if (Constantes.METODOS_SQL_HIBRIDOS.contains(metodo) && simbolo(indice - 1, '.') && identificador(indice - 2)) {
                cwe = Constantes.CWE_SQL;
                inicio = indice - 2;
                preparada = Constantes.METODO_PREPARE.equals(metodo);
            } else if (Constantes.METODO_EXEC.equals(metodo) && esRuntime(indice)) {
                cwe = Constantes.CWE_COMANDOS;
                inicio = indice - 6;
            } else if (Constantes.TIPO_FILE.equals(metodo) && palabra(indice - 1, Constantes.PALABRA_NEW)) {
                cwe = Constantes.CWE_RUTAS;
                inicio = indice - 1;
                constructor = true;
            }
            int fin = cerrarParentesis(indice + 1);
            if (cwe == null || fin < 0 || fin == indice + 2 || tieneComaSuperior(indice + 2, fin)) {
                continue;
            }
            Valor valor = java ? resolver(indice + 2, fin, tokens.get(indice).bloque(), 0) : desconocido();
            operaciones.add(new Operacion(cwe, inicio, fin, preparada, constructor, valor));
        }
    }

    private boolean esRuntime(int indice) {
        return palabra(indice - 6, Constantes.TIPO_RUNTIME) && simbolo(indice - 5, '.')
                && palabra(indice - 4, Constantes.METODO_GET_RUNTIME) && simbolo(indice - 3, '(')
                && simbolo(indice - 2, ')') && simbolo(indice - 1, '.')
                && !tipoSombreado(Constantes.TIPO_RUNTIME);
    }

    private boolean tipoSombreado(String nombre) {
        for (int indice = 1; indice < tokens.size(); indice++) {
            if (palabra(indice, nombre) && Constantes.TIPOS_SOMBREADOS_HIBRIDOS.contains(tokens.get(indice - 1).texto())) {
                return true;
            }
        }
        return false;
    }

    private Valor resolver(int inicio, int fin, int bloque, int profundidad) {
        if (inicio >= fin || profundidad > 16) {
            return desconocido();
        }
        if (simbolo(inicio, '(') && cerrarParentesis(inicio) == fin - 1) {
            return resolver(inicio + 1, fin - 1, bloque, profundidad + 1);
        }
        int nivel = 0;
        for (int indice = inicio; indice < fin; indice++) {
            if (simbolo(indice, '(')) nivel++;
            if (simbolo(indice, ')')) nivel--;
            if (nivel == 0 && simbolo(indice, '+')) {
                return concatenar(resolver(inicio, indice, bloque, profundidad + 1),
                        resolver(indice + 1, fin, bloque, profundidad + 1));
            }
        }
        if (fin == inicio + 1 && tokens.get(inicio).literal()) {
            return new Valor(TipoValor.CONSTANTE, Set.of(), List.of());
        }
        if (fin == inicio + 1 && identificador(inicio)) {
            return resolverVariable(inicio, bloque, profundidad);
        }
        for (int indice = inicio; indice + 1 < fin; indice++) {
            if (Constantes.METODOS_ORIGEN_HIBRIDOS.contains(tokens.get(indice).texto())
                    && simbolo(indice + 1, '(') && cerrarParentesis(indice + 1) == fin - 1
                    && (indice == inicio || indice == inicio + 2 && simbolo(indice - 1, '.'))) {
                return new Valor(TipoValor.EXTERNO, Set.of(),
                        List.of(paso(TipoEvidencia.ORIGEN, inicio, fin - 1, Constantes.EVIDENCIA_ORIGEN)));
            }
        }
        return desconocido();
    }

    private Valor resolverVariable(int posicion, int bloque, int profundidad) {
        String variable = tokens.get(posicion).texto();
        List<Declaracion> candidatas = declaraciones.stream().filter(declaracion -> declaracion.bloque() == bloque
                && declaracion.variable().equals(variable) && declaracion.fin() < posicion).toList();
        if (candidatas.size() != 1) {
            return desconocido();
        }
        Declaracion declaracion = candidatas.getFirst();
        if (tieneReasignaciones(declaracion, posicion)) {
            return desconocido();
        }
        Valor inicial = resolver(declaracion.expresionInicio(), declaracion.expresionFin(), bloque, profundidad + 1);
        Set<Declaracion> usadas = new LinkedHashSet<>(inicial.declaraciones());
        usadas.add(declaracion);
        List<Evidencia> evidencia = new ArrayList<>(inicial.evidencia());
        evidencia.add(paso(TipoEvidencia.PROPAGACION, declaracion.inicio(), declaracion.fin(), Constantes.EVIDENCIA_PROPAGACION));
        return new Valor(inicial.tipo(), Set.copyOf(usadas), List.copyOf(evidencia));
    }

    private boolean tieneReasignaciones(Declaracion declaracion, int hasta) {
        for (int indice = declaracion.fin() + 1; indice < hasta; indice++) {
            if (!palabra(indice, declaracion.variable())) continue;
            if (simbolo(indice + 1, '=') || simbolo(indice + 2, '=')
                    || simbolo(indice + 1, '+') && simbolo(indice + 2, '+')
                    || simbolo(indice + 1, '-') && simbolo(indice + 2, '-')) {
                return true;
            }
        }
        return false;
    }

    private Valor concatenar(Valor primero, Valor segundo) {
        Set<Declaracion> usadas = new LinkedHashSet<>(primero.declaraciones());
        usadas.addAll(segundo.declaraciones());
        List<Evidencia> evidencia = new ArrayList<>(primero.evidencia());
        evidencia.addAll(segundo.evidencia());
        TipoValor tipo = primero.tipo() == TipoValor.DESCONOCIDO || segundo.tipo() == TipoValor.DESCONOCIDO
                ? TipoValor.DESCONOCIDO : primero.tipo() == TipoValor.EXTERNO || segundo.tipo() == TipoValor.EXTERNO
                ? TipoValor.EXTERNO : TipoValor.CONSTANTE;
        return new Valor(tipo, Set.copyOf(usadas), List.copyOf(evidencia));
    }

    private boolean esFlujoLineal(Operacion operacion) {
        int bloque = tokens.get(operacion.inicio()).bloque();
        Set<Integer> ancestros = new LinkedHashSet<>();
        for (int actual = bloque; actual != 0; actual = padres.getOrDefault(actual, 0)) ancestros.add(actual);
        boolean control = tokens.stream().anyMatch(token -> ancestros.contains(token.bloque())
                && Constantes.CONTROLES_HIBRIDOS.contains(token.texto()));
        if (control) return false;
        int inicio = operacion.valor().declaraciones().stream().mapToInt(Declaracion::inicio)
                .min().orElse(operacion.inicio());
        for (int indice = inicio; indice <= operacion.fin(); indice++) {
            int posicion = indice;
            boolean permitida = posicion >= operacion.inicio() || simbolo(posicion, ';')
                    || operacion.valor().declaraciones().stream()
                            .anyMatch(declaracion -> declaracion.inicio() <= posicion && posicion <= declaracion.fin());
            if (!permitida) return false;
        }
        return !operacion.preparada();
    }

    private Evidencia paso(TipoEvidencia tipo, int inicio, int fin, String descripcion) {
        return new Evidencia(tipo, tokens.get(inicio).linea(), tokens.get(fin).linea(), descripcion);
    }

    private int cerrarParentesis(int inicio) {
        int nivel = 0;
        for (int indice = inicio; indice < tokens.size(); indice++) {
            if (simbolo(indice, '(')) nivel++;
            if (simbolo(indice, ')') && --nivel == 0) return indice;
        }
        return -1;
    }

    private boolean tieneComaSuperior(int inicio, int fin) {
        int nivel = 0;
        for (int indice = inicio; indice < fin; indice++) {
            if (simbolo(indice, '(')) nivel++;
            if (simbolo(indice, ')')) nivel--;
            if (nivel == 0 && simbolo(indice, ',')) return true;
        }
        return false;
    }

    private boolean palabra(int indice, String palabra) {
        return indice >= 0 && indice < tokens.size() && !tokens.get(indice).literal() && tokens.get(indice).texto().equals(palabra);
    }

    private boolean simbolo(int indice, char simbolo) {
        return indice >= 0 && indice < tokens.size() && tokens.get(indice).texto().length() == 1
                && !tokens.get(indice).literal() && tokens.get(indice).texto().charAt(0) == simbolo;
    }

    private boolean identificador(int indice) {
        return indice >= 0 && indice < tokens.size() && !tokens.get(indice).literal()
                && Character.isJavaIdentifierStart(tokens.get(indice).texto().charAt(0));
    }

    private Valor desconocido() {
        return new Valor(TipoValor.DESCONOCIDO, Set.of(), List.of());
    }

    private boolean tokenizar(String codigo) {
        Deque<Integer> bloques = new ArrayDeque<>();
        bloques.push(0);
        int siguienteBloque = 0;
        int linea = 1;
        for (int indice = 0; indice < codigo.length();) {
            char caracter = codigo.charAt(indice);
            if (!java && caracter == '`') return false;
            if (!java && caracter == '#') {
                while (indice < codigo.length() && codigo.charAt(indice) != '\n' && codigo.charAt(indice) != '\r') indice++;
                continue;
            }
            if (caracter == '\\' && indice + 1 < codigo.length() && codigo.charAt(indice + 1) == 'u') return false;
            if (Character.isWhitespace(caracter)) {
                if (caracter == '\n' || caracter == '\r' && (indice + 1 == codigo.length() || codigo.charAt(indice + 1) != '\n')) linea++;
                indice++;
                continue;
            }
            if (caracter == '/' && indice + 1 < codigo.length() && codigo.charAt(indice + 1) == '/') {
                while (indice < codigo.length() && codigo.charAt(indice) != '\n' && codigo.charAt(indice) != '\r') indice++;
                continue;
            }
            if (caracter == '/' && indice + 1 < codigo.length() && codigo.charAt(indice + 1) == '*') {
                indice += 2;
                while (indice + 1 < codigo.length() && !(codigo.charAt(indice) == '*' && codigo.charAt(indice + 1) == '/')) {
                    if (codigo.charAt(indice) == '\n') linea++;
                    indice++;
                }
                if (indice + 1 >= codigo.length()) return false;
                indice += 2;
                continue;
            }
            int inicio = indice++;
            boolean literal = caracter == '"';
            if (literal || caracter == '\'') {
                if (literal && indice + 1 < codigo.length() && codigo.charAt(indice) == '"' && codigo.charAt(indice + 1) == '"') return false;
                boolean cerrada = false;
                while (indice < codigo.length()) {
                    char actual = codigo.charAt(indice++);
                    if (actual == '\n' || actual == '\r') return false;
                    if (actual == '\\') {
                        if (indice < codigo.length() && codigo.charAt(indice) == 'u') return false;
                        indice++;
                    } else if (actual == caracter) {
                        cerrada = true;
                        break;
                    }
                }
                if (!cerrada) return false;
            } else if (Character.isJavaIdentifierStart(caracter)) {
                while (indice < codigo.length() && Character.isJavaIdentifierPart(codigo.charAt(indice))) indice++;
            }
            if (caracter == '}') {
                if (bloques.size() == 1) return false;
                bloques.pop();
            }
            tokens.add(new Token(codigo.substring(inicio, indice), linea, bloques.peek(), literal));
            if (caracter == '{') {
                padres.put(++siguienteBloque, bloques.peek());
                bloques.push(siguienteBloque);
            }
        }
        return bloques.size() == 1;
    }

    public record Ubicacion(Integer operacion, int lineaOperacion, EstadoRevision estado,
            String justificacion, List<Evidencia> evidencia, boolean ambigua) {
    }

    private enum TipoValor { CONSTANTE, EXTERNO, DESCONOCIDO }
    private record Token(String texto, int linea, int bloque, boolean literal) {
    }
    private record Declaracion(String variable, int inicio, int fin, int bloque, int expresionInicio, int expresionFin) {
    }
    private record Valor(TipoValor tipo, Set<Declaracion> declaraciones, List<Evidencia> evidencia) {
    }
    private record Operacion(String cwe, int inicio, int fin, boolean preparada, boolean constructorArchivo, Valor valor) {
    }
}
