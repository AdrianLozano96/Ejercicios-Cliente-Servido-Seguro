package org.adrianl.jca.seguro;
import java.io.*;
import javax.net.ssl.*;
public class ClienteSeguro {

    public static void main( String[] args ) throws IOException {
        // Obtenemos el objeto de tipo Factory para crear sockets SSL
        SSLSocketFactory fact = (SSLSocketFactory)SSLSocketFactory.getDefault();
        // Utilizamos el objeto para crear un socket seguro
        SSLSocket socketSsl = (SSLSocket)fact.createSocket( "localhost",9999 );
        // Consola desde la que leemos la entrada del usuario
        BufferedReader entrada = new BufferedReader(new InputStreamReader(System.in));
        // Canal de comunicación con el servidor de eco
        BufferedWriter salida = new BufferedWriter(new OutputStreamWriter(socketSsl.getOutputStream()));
        String linea = null;
        System.out.println( "Listo..." );
        // Vamos enviando las líneas al servidor
        while( (linea = entrada.readLine()) != null ) {
            salida.write( linea+'\n' );
            salida.flush();
        }
    }
    //El comando para invocar al cliente es el siguiente:

    //java -Djavax.net.ssl.trustStore=TrustSSL -Djavax.net.ssl.trustStorePassword=cualquiera Cliente

}
