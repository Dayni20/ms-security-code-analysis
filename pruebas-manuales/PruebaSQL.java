import java.sql.Statement;
import java.sql.SQLException;
import jakarta.servlet.http.HttpServletRequest;

public class PruebaSQL {

    public void consultarCliente(
            HttpServletRequest request,
            Statement statement) throws SQLException {

        String nombre = request.getParameter("nombre");

        String consulta = "SELECT * FROM clientes WHERE nombre = '"
                + nombre + "'";

        statement.executeQuery(consulta);
    }
}
