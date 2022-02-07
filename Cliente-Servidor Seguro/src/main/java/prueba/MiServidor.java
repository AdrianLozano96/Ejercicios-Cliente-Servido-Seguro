package prueba;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.File;
import java.io.IOException;

public class MiServidor {

    private final int PUERTO = 9696;
    private SSLServerSocketFactory serverFactory;
    private SSLServerSocket servidorControl;
    private SSLSocket cliente = null;
    private boolean salir = false;
    // Patron Singleton -> Unsa sola instancia
    private static MiServidor servidor;
    private MiServidor() {}
    public static MiServidor initServer() throws IOException {
        if (servidor == null) {
            servidor = new MiServidor();
            servidor.initControl();
        }
        return servidor;
    }
    private void initControl() throws IOException {
        //- Preparamos conexion
        // De donde sacamos los datos
        String fichero = System.getProperty("user.dir")+ File.separator+"cert"+File.separator+"AlmacenSSL.jks";
        System.setProperty("javax.net.ssl.keyStore", fichero);
        System.setProperty("javax.net.ssl.keyStorePassword","1234567");
        // Nos anunciamos como servidorControl de tipo SSL
        this.serverFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        this.servidorControl = (SSLServerSocket) serverFactory.createServerSocket(this.PUERTO);
        System.out.println("Servidor->Listo. Esperando cliente...");
        //- Tratar Conexión Trabajamos con ella
        while (!salir) {// Escuchamos hasta aburrirnos, es decir, hasta que salgamos
            //- Aceptamos la conexion
            cliente = (SSLSocket)servidorControl.accept();
            System.out.println("Servidor->Llega el cliente: " + cliente.getInetAddress() +":"+cliente.getPort());
            //- Procesamos el cliente
            System.out.println("Servidor->Iniciando sistema de control");
            MiControlCliente gc = new MiControlCliente(cliente);
            gc.start();
        }
        //- Cerramos la conexion
        // Cerramos el cliente y el servidorControl
        cliente.close();
        servidorControl.close();
        System.out.println("Servidor->Cerrando la conexión");
        System.exit(0);
    }
}