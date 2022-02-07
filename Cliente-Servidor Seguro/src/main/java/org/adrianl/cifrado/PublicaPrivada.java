package org.adrianl.cifrado;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class PublicaPrivada {

    /**
     * Leemos la clave pública de un fichero
     *
     * @param fichero fichero de clave pública
     * @return clave pública
     * @throws Exception
     */
    public static PublicKey cargarClavePublicaRSA(String fichero) throws Exception {
        FileInputStream fis = new FileInputStream(fichero);
        int numBtyes = fis.available();
        byte[] bytes = new byte[numBtyes];
        fis.read(bytes);
        fis.close();

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        KeySpec keySpec = new X509EncodedKeySpec(bytes);
        PublicKey keyFromBytes = keyFactory.generatePublic(keySpec);
        return keyFromBytes;
    }

    /**
     * Carga la Clave Privada desde fichero
     *
     * @param fichero fichero de clave privada
     * @return clave privada
     * @throws Exception
     */
    public static PrivateKey cargarClavePrivadaRSA(String fichero) throws Exception {
        FileInputStream fis = new FileInputStream(fichero);
        int numBtyes = fis.available();
        byte[] bytes = new byte[numBtyes];
        fis.read(bytes);
        fis.close();

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        KeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
        PrivateKey keyFromBytes = keyFactory.generatePrivate(keySpec);
        return keyFromBytes;
    }

    /**
     * Salva el par de claves (privada/pública) en un fichero
     *
     * @param key     clave
     * @param fichero fichero de claves
     * @throws Exception
     */
    public static void salvarClavesRSA(Key key, String fichero) throws Exception {
        byte[] publicKeyBytes = key.getEncoded();
        FileOutputStream fos = new FileOutputStream(fichero);
        fos.write(publicKeyBytes);
        fos.close();
    }

}
