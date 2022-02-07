package org.adrianl.cliente_servidor;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.File;
import java.io.IOException;

public class Servidor {

    SSLServerSocketFactory serverFactory;
    SSLServerSocket serverSocket;
    SSLSocket cliente;
    boolean salir = false;
    int puerto = 9696;
    private static Servidor servidor;
    private Servidor(){}
    public static Servidor initServer() throws IOException {
        if(servidor == null) {
            servidor = new Servidor();
            servidor.initControl();
        }
        return servidor;
    }

    private void initControl() throws IOException {

        String fichero = System.getProperty("user.dir")+ File.separator+"cert"+File.separator+"AlmacenSSL.jks";
        System.setProperty("javax.net.ssl.keyStore", fichero);
        System.setProperty("javax.net.ssl.keyStorePassword","1234567");
        this.serverFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        this.serverSocket = (SSLServerSocket) serverFactory.createServerSocket(this.puerto);
        System.out.println("Servidor Listo");
        while(!salir){
            System.out.println("Seridor Iniciandose");
            cliente = (SSLSocket)serverSocket.accept();
            System.out.println("Servidor->Llega el cliente: " + cliente.getInetAddress() +":"+cliente.getPort());
            GestorClientes gc = new GestorClientes(cliente);
            gc.start();
        }
        cliente.close();
        serverSocket.close();
        //System.exit(0);








    }
}
