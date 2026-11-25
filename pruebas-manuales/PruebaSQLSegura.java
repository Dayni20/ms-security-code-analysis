import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import jakarta.servlet.http.HttpServletRequest;

public class PruebaSQLSegura {

    public void consultarCliente(
            HttpServletRequest request,
            Connection connection) throws SQLException {

        String nombre = request.getParameter("nombre");

        String consulta = "SELECT * FROM clientes WHERE nombre = ?";

        try (PreparedStatement statement =
                     connection.prepareStatement(consulta)) {

            statement.setString(1, nombre);
            statement.executeQuery();
        }
    }
}