package org.adrianl.jca.cifrado_simetrico;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

public class Simetrico {

    public void simetrico() throws NoSuchAlgorithmException {
        //Se debe indicar el nombre (alias) del algoritmo de cifrado y, si son necesarios
        // (en caso de cifradores de bloque), una especificación del modo de funcionamiento (ECB, CBC, ...) y
        // del algoritmo de relleno. (Opcionalmente puede ser necesario indicar nombre del provider).

        //static Cipher getInstance (String transformation);
        //static Cipher getInstance (String transformation, String provider);

        //Creación de la clave.
        //Las claves se gestionan mediante objetos que implementan el interfaz SecretKey (que a su vez hereda del interfaz Key).
        //Las claves se crean empleando un objeto KeyGenerator.
        //Creación del KeyGenerator empleando un método factoría (se debe indicar el alias del algoritmo de cifrado y, opcionalmente,
        //el nombre del provider):
        KeyGenerator generadorDES = KeyGenerator.getInstance("DES");

        //Configuración del KeyGenerator (normalmente especificación del tamaño de clave):
        generadorDES.init(56); // clave de 56 bits

        //Creación de la clave:
        SecretKey clave = generadorDES.generateKey();
    }

}
