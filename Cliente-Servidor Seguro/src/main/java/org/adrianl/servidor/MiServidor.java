package org.adrianl.servidor;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.File;
import java.io.IOException;

public class MiServidor {

    private final int PUERTO = 6666;
    private SSLServerSocketFactory serverFactory;
    private SSLServerSocket servidorControl;
    private SSLSocket cliente = null;
    private boolean salir = false;
    // Patron Singleton -> Unsa sola instancia
    private static MiServidor servidor;
    private MiServidor() {}
    public static MiServidor initServer() {
        if (servidor == null) {
            servidor = new MiServidor();
            servidor.initControl();
        }
        return servidor;
    }
    private void initControl() {
        prepararConexion(); // Prparamos conexion
        tratarConexion();   // Trabajamos con ella
        cerrarConexion();   // Cerramos la conexion
    }

    private void prepararConexion() {
        try {
            // De donde sacamos los datos
            String fichero = System.getProperty("user.dir")+ File.separator+"cert"+File.separator+"AlmacenSSL.jks";
            System.setProperty("javax.net.ssl.keyStore", fichero);
            System.setProperty("javax.net.ssl.keyStorePassword","1234567");
            // Nos anunciamos como servidorControl de tipo SSL
            this.serverFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            this.servidorControl = (SSLServerSocket) serverFactory.createServerSocket(this.PUERTO);
            System.out.println("Servidor->Listo. Esperando cliente...");
        } catch (IOException ex) {
            System.err.println("Servidor->ERROR: apertura de puerto " + ex.getMessage());
            System.exit(-1);
        }
    }

    private void tratarConexion() {
        while (!salir) {// Escuchamos hasta aburrirnos, es decir, hasta que salgamos
            //Aceptamos la conexion
            aceptarConexion();
            // Procesamos el cliente
            procesarCliente();
        }
    }

    private void aceptarConexion() {
        // Aceptamos la petición
        try {
            cliente = (SSLSocket)servidorControl.accept();
            System.out.println("Servidor->Llega el cliente: " + cliente.getInetAddress() +":"+cliente.getPort());
        } catch (IOException ex) {
            System.err.println("Servidor->ERROR: aceptar conexiones " + ex.getMessage());
        }
    }

    private void procesarCliente() {
        System.out.println("Servidor->Iniciando sistema de control");
        MiControlCliente gc = new MiControlCliente(cliente);
        gc.start();
    }

    private void cerrarConexion() {
        try {
            // Cerramos el cliente y el servidorControl
            cliente.close();
            servidorControl.close();
            System.out.println("Servidor->Cerrando la conexión");
            System.exit(0);
        } catch (IOException ex) {
            System.err.println("Servidor->ERROR: Cerrar Conexiones" + ex.getMessage());
        }
    }
}