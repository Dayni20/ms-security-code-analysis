import java.io.IOException;

public class PruebaComandoSeguro {

    public void ejecutar() throws IOException {

        String comando = "whoami";

        Runtime.getRuntime().exec(comando);
    }
}