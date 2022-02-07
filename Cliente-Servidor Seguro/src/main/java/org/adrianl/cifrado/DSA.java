package org.adrianl.cifrado;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class DSA {

    /**
     * Crea una clave de firma DSA y la almacena en fichero
     *
     * @param fichero fichero de claves
     */
    public void crearClavesDSA(String fichero) {
        try {
            // Generar el par de claves
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
            // Lo inicializamos (antes no lo he puestopara que seapor defecto)
            SecureRandom numero = SecureRandom.getInstance("SHA1PRNG");
            keyPairGenerator.initialize(1024, numero);
            // obtenemos el par de claves
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // Se salva y recupera de fichero la clave publica
            this.salvarClavesDSA(publicKey, fichero + "-dsa-public.dat");
            this.salvarClavesDSA(privateKey, fichero + "-dsa-private.dat");
        } catch (Exception ex) {
            System.err.println("Error al crear clave DSA: " + ex.getLocalizedMessage());
        }
    }

    /**
     * Salva una clave Privada o pública DSA en fichero
     *
     * @param key     clave
     * @param fichero fichero
     * @throws Exception
     */
    public void salvarClavesDSA(Key key, String fichero) throws Exception {
        byte[] publicKeyBytes = key.getEncoded();
        FileOutputStream fos = new FileOutputStream(fichero);
        fos.write(publicKeyBytes);
        fos.close();
    }

    /**
     * Leemos la clave pública de un fichero
     *
     * @param fichero fichero de clave pública
     * @return clave pública
     * @throws Exception
     */
    public PublicKey cargarClavePublicaDSA(String fichero) throws Exception {
        FileInputStream fis = new FileInputStream(fichero);
        int numBtyes = fis.available();
        byte[] bytes = new byte[numBtyes];
        fis.read(bytes);
        fis.close();

        KeyFactory keyFactory = KeyFactory.getInstance("DSA");
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
    public PrivateKey cargarClavePrivadaDSA(String fichero) throws Exception {
        FileInputStream fis = new FileInputStream(fichero);
        int numBtyes = fis.available();
        byte[] bytes = new byte[numBtyes];
        fis.read(bytes);
        fis.close();

        KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        KeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
        PrivateKey keyFromBytes = keyFactory.generatePrivate(keySpec);
        return keyFromBytes;
    }

    /**
     * Firma un texto mediante DSA
     *
     * @param mensaje       mensaje a firmar
     * @param privateKeyFile Fichero de la clave privada
     * @return cadena cifrada
     */
    public String firmarDSA(String mensaje, String privateKeyFile) {
        try {
            PrivateKey privateKey = this.cargarClavePrivadaDSA(privateKeyFile);
            Signature dsa = Signature.getInstance("SHA1withDSA");
            dsa.initSign(privateKey);
            dsa.update(mensaje.getBytes("UTF-8"));
            byte[] firmado = dsa.sign(); // obtenemos la firma
            return Base64.getEncoder().encodeToString(firmado);
        } catch (Exception ex) {
            System.err.println("Error al firmar con DSA: " + ex.getLocalizedMessage());
        }
        return null;
    }

    /**
     * Comprueba la firma a una cadena
     *
     * @param original      cadena original
     * @param firmado       cadena firmada
     * @param publicKeyFile fichero de clave pública
     * @return
     */
    public boolean verificarDSA(String original, String firmado, String publicKeyFile) {
        try {
            PublicKey publicKey = this.cargarClavePublicaDSA(publicKeyFile);
            Signature dsa = Signature.getInstance("SHA1withDSA");
            dsa.initVerify(publicKey);
            dsa.update(original.getBytes("UTF-8"));
            byte[] firma = Base64.getDecoder().decode(firmado);
            boolean check = dsa.verify(firma);
            return check;
        } catch (Exception ex) {
            System.err.println("Error al comprobar la firma DSA: " + ex.getLocalizedMessage());
        }
        return false;
    }

}
