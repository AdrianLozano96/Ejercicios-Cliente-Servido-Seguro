package org.adrianl.jca.cifrado_simetrico;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Sha {

    public void sha() throws NoSuchAlgorithmException {
        //Para generar estas cadenas de resumen utilizaremos la clase MessageDigest de Java que permite
        // a las aplicaciones implementar algoritmos de resumen de mensajes, como MD5, SHA-1, o SHA-256. Algunos de sus métodos son:
        //Implementación de un algoritmo de resumen especificado.
        MessageDigest md = MessageDigest.getInstance("SHA");
        //Introducir el texto a resumir.
        String texto = "Hola";
        byte datos[] = texto.getBytes(); //Texto en bytes
        md.update(datos);
        //Realizar el resumen.
        byte resumenCalculado[] = md.digest();
        //Comprobar dos resúmenes.
        //if (MessageDigest.isEqual(resumenOriginal, resumenCalculado)){}
    }

}
