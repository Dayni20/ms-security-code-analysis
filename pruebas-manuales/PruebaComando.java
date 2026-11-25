import java.io.IOException;
import jakarta.servlet.http.HttpServletRequest;

public class PruebaComando {

    public void ejecutar(HttpServletRequest request)
            throws IOException {

        String comando = request.getParameter("comando");

        Runtime.getRuntime().exec(comando);
    }
}