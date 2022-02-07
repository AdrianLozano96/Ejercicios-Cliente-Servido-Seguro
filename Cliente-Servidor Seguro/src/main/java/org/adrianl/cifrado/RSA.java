package org.adrianl.cifrado;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class RSA {

    /**
     * Crea las claves de cifrado RSA y las almacena en un fichero
     *
     * @param fichero
     */
    public void crearClavesRSA(String fichero) {
        try {
            // Generar el par de claves
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // Se salva y recupera de fichero la clave publica
            PublicaPrivada.salvarClavesRSA(publicKey, fichero + "-rsa-public.dat");
            PublicaPrivada.salvarClavesRSA(privateKey, fichero + "-rsa-private.dat");
        } catch (Exception ex) {
            System.err.println("Error al crear clave RSA: " + ex.getLocalizedMessage());
        }
    }

    /**
     * Cifra un texto mediante RSA
     *
     * @param mensaje       mensaje a cifrar
     * @param publicKeyFile Fichero de la clave pública
     * @return cadena cifrada
     */
    public String cifrarRSA(String mensaje, String publicKeyFile) {
        try {
            PublicKey publicKey = PublicaPrivada.cargarClavePublicaRSA(publicKeyFile);
            Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsa.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encriptado = rsa.doFinal(mensaje.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(encriptado);
        } catch (Exception ex) {
            System.err.println("Error al cifrar con RSA: " + ex.getLocalizedMessage());
        }
        return null;
    }

    /**
     * Descifra una cadena mediante RSA
     *
     * @param mensaje        mensaje a cifrar
     * @param privateKeyFile fichero de clave provada
     * @return mensje cifrado
     */
    public String descifrarRSA(String mensaje, String privateKeyFile) {
        try {
            PrivateKey privateKey = PublicaPrivada.cargarClavePrivadaRSA(privateKeyFile);
            Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsa.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] encriptado = Base64.getDecoder().decode(mensaje);
            byte[] desencriptado = rsa.doFinal(encriptado);
            return new String(desencriptado);
        } catch (Exception ex) {
            System.err.println("Error al descifrar con RSA: " + ex.getLocalizedMessage());
        }
        return null;
    }

}
