import java.io.File;
import javax.servlet.http.HttpServletRequest;

public class PruebaRuta {

    public void consultarArchivo(HttpServletRequest request) {

        String nombreArchivo = request.getParameter("archivo");

        String ruta = "documentos/" + nombreArchivo;

        File archivo = new File(ruta);
    }
}