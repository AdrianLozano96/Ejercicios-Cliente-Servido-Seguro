package prueba;

import java.io.IOException;

public class AppServer {
    public static void main(String[] args) {
        try {
            MiServidor.initServer();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
