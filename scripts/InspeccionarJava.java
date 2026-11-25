import java.nio.file.*;
import java.util.*;
import javax.tools.*;
import com.sun.source.tree.*;
import com.sun.source.util.*;

public class InspeccionarJava {
    static String json(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c == '\n') b.append("\\n");
            else if (c == '\r') b.append("\\r");
            else if (c == '\t') b.append("\\t");
            else if (c < 32) b.append(String.format("\\u%04x", (int)c));
            else b.append(c);
        }
        return b.append('"').toString();
    }
    public static void main(String[] args) throws Exception {
        System.setOut(new java.io.PrintStream(System.out, true, java.nio.charset.StandardCharsets.UTF_8));
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        try (StandardJavaFileManager manager = compiler.getStandardFileManager(null, null, java.nio.charset.StandardCharsets.UTF_8)) {
            DiagnosticCollector<JavaFileObject> diagnosticos = new DiagnosticCollector<>();
            JavacTask tarea = (JavacTask) compiler.getTask(null, manager, diagnosticos, List.of("-proc:none"), null, manager.getJavaFileObjects(args));
            for (CompilationUnitTree unidad : tarea.parse()) {
                SourcePositions posiciones = Trees.instance(tarea).getSourcePositions();
                for (Tree tipo : unidad.getTypeDecls()) if (tipo instanceof ClassTree clase) {
                    StringJoiner miembros = new StringJoiner(",");
                    for (Tree miembro : clase.getMembers()) {
                        String nombre;
                        String tipoMiembro;
                        if (miembro instanceof MethodTree metodo) { nombre = metodo.getName().toString(); tipoMiembro = "metodo"; }
                        else if (miembro instanceof VariableTree campo) { nombre = campo.getName().toString(); tipoMiembro = "campo"; }
                        else continue;
                        long inicio = posiciones.getStartPosition(unidad, miembro), fin = posiciones.getEndPosition(unidad, miembro);
                        StringJoiner llamadas = new StringJoiner(",");
                        new TreeScanner<Void,Void>() {
                            public Void visitMethodInvocation(MethodInvocationTree nodo, Void v) {
                                ExpressionTree selector = nodo.getMethodSelect();
                                if (selector instanceof IdentifierTree identificador) llamadas.add(json(identificador.getName().toString()));
                                return super.visitMethodInvocation(nodo, v);
                            }
                        }.scan(miembro, null);
                        miembros.add("{\"tipo\":"+json(tipoMiembro)+",\"nombre\":"+json(nombre)+",\"inicio\":"+inicio+",\"fin\":"+fin+",\"lineaInicio\":"+unidad.getLineMap().getLineNumber(inicio)+",\"lineaFin\":"+unidad.getLineMap().getLineNumber(fin-1)+",\"ast\":"+json(miembro.toString())+",\"llamadas\":["+llamadas+"]}");
                    }
                    System.out.println("{\"archivo\":"+json(Paths.get(unidad.getSourceFile().toUri()).toString())+",\"clase\":"+json(clase.getSimpleName().toString())+",\"miembros\":["+miembros+"]}");
                }
            }
            if (diagnosticos.getDiagnostics().stream().anyMatch(d -> d.getKind() == Diagnostic.Kind.ERROR)) throw new IllegalArgumentException(diagnosticos.getDiagnostics().toString());
        }
    }
}
