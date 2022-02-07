package org.adrianl.jca.cifrado_asimetrico;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

//Instalación y uso de Provider Bouncy Castle.  Para usar las clases de JCA/JCE ofrecidas por BounceCastle,
// basta con incluir en el código que lo utilice la siguiente orden de importación:
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
public class Asimetrico {

    public void asimetrico() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        //Dentro del código será necesario indicar la carga del provider BouncyCastle del siguiente modo:
        //Security.addProvider(new BouncyCastleProvider());

        //Este código se deberá situar antes de cualquier uso que se realice de este provider. La abreviatura
        // que identifica a este provider es ''BC'' y deberá indicarse cuando se solicite alguna de las implementaciones
        // de algoritmos que ofrece el provider BouncyCastle.
        Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS1Padding", "BC");
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");

        //Creación de claves asimétricas.   Las claves se gestionan mediante objetos que implementan el interfaz
        // PublicKey y PrivateKey (que a su vez hereda del interfaz Key)
        //Las claves se crean empleando un objeto KeyPairGenerator específico para cada algoritmo asimétrico.
        //Creación del KeyPairGenerator empleando un método factoría
        //Se debe indicar el alias del algoritmo de cifrado y, OBLIGATORIAMENTE, el nombre del provider
        // [inicialmente el provider por defecto ''SUN'' no incluía RSA por limitaciones a la exportación de algoritmos de cifrado]).
        //Security.addProvider(new BouncyCastleProvider());  // Cargar el provider BC
        KeyPairGenerator keyGenRSA = KeyPairGenerator.getInstance("RSA", "BC");
        // Usa BouncyCastle
        //Configuración del KeyPairGenerator (normalmente especificación del tamaño de clave).
        //gkeyGenRSA.initialize(512);   // clave RSA de 512 bits
        //Creación del par de claves (y recuperación de las claves pública y privada).

        KeyPair clavesRSA = keyGenRSA.generateKeyPair();
        PrivateKey clavePrivada = clavesRSA.getPrivate();
        PublicKey clavePublica = clavesRSA.getPublic();

    }

}
