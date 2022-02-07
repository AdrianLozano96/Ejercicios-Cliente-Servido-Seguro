package org.adrianl.jca.seguro;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class ServidorSeguro {
    public static void main( String[] args ) throws IOException {
        // Obtenemos el objeto de tipo Factory para crear sockets SSL
        SSLServerSocketFactory fact =    (SSLServerSocketFactory)SSLServerSocketFactory.getDefault();
        // Utilizamos el objeto para crear un socket servidor seguro
        SSLServerSocket socketServidorSsl =  (SSLServerSocket)fact.createServerSocket( 9999 );
        SSLSocket socketSsl = (SSLSocket)socketServidorSsl.accept();

        // Creamos un canal de entrada sobre el socket seguro que hemos abierto
        BufferedReader entrada = new BufferedReader(new InputStreamReader(socketSsl.getInputStream()));

        String linea = null;
        System.out.println( "Esperando..." );
        // Presentamos todas las líneas que vayan llegan entrando en
        // el canal a través del socket
        while( (linea = entrada.readLine()) != null ) {
            System.out.println( linea );
            System.out.flush();
        }
    }

    //Para ejecutar el servidor es necesario indicar el certificado que se utilizará. Si el certificado se llamara:
    // claveSSL.crt, el comando a utilizar para la ejecución del servidor será:

    //java -Djavax.net.ssl.keyStore=StoreSSL -Djavax.net.ssl.keyStorePassword=cualquiera Servidor
}
