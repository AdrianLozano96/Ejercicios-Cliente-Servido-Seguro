package org.adrianl.jca.firma_digital;

import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

public class GenerarClaves {

    public void generarClaves() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException, InvalidKeySpecException {
        //1.- Generar el par de claves.
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");  //La clase KeyPairGenerator nos permite gernerar el par de claves.
        SecureRandom numero = SecureRandom.getInstance("SHA1PRNG");
        keyGen.initialize(1024, numero);
        //Creamos el par de claves (privada y pública).
        KeyPair par = keyGen.generateKeyPair();
        PrivateKey clavepriv = par.getPrivate();
        PublicKey  clavepubl = par.getPublic();

        //2.- Almacenar las claves y/o transmitirlas a sus respectivos destinatarios. Ver otra clase
        AlmacenaRecuperarClaves.almacenarClaves(clavepriv,clavepubl);
        AlmacenaRecuperarClaves.recuperarClaves(clavepriv,clavepubl);
        //3.- Firmar los datos. Usaremos la clase Signature. Se firma con la clave privada y se verifica con la pública.
        // La firma es devuelta como un array de bytes. Firmamos con la clave privada el mensaje.
        //Al especificar el nombre del algoritmo de firma se debe especificar, también,
        //el nombre del algoritmo resumen utilizado por el algoritmo de firma.
        //Tendremos dos:
        //  - SHAwithDSA --> firma con DSA resumen con SHA.
        //  - MD5withRSA --> firma con RSA resumen con MD5.
        Signature dsa = Signature.getInstance("SHA1withDSA");
        dsa.initSign(clavepriv);
        String mensaje = "Texto a firmar";
        dsa.update(mensaje.getBytes());
        byte []firma = dsa.sign(); //Mensaje firmado.

        //4.- Verificar los datos. Usaremos la clase Signature. Se verificará con la pública.
        //El receptor del mensaje, verifica con clave pública el mensaje firmado.
        Signature verifica_dsa = Signature.getInstance("SHA1withDSA");
        verifica_dsa.initVerify(clavepubl);
        verifica_dsa.update(mensaje.getBytes());
        boolean check = verifica_dsa.verify(firma);
    }

}
