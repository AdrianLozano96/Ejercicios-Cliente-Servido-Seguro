package org.adrianl.cliente_servidor;

import java.io.IOException;

public class ServidorApp {
    public static void main(String[] args) throws IOException {
        try {
            Servidor.initServer();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
