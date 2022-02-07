package org.adrianl.cifrado;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.security.Key;
import java.util.Base64;

public class AES {

    /**
     * Cifra un mensaje con AES 128 bits
     *
     * @param mensaje mensaje a cofrar
     * @param pass    contraseña para cifrar
     * @return mensaje cifrado y codificado ademas en base64
     */
    public String cifrarAES(String mensaje, String pass) {
        try {
            // Generamos una clave de 128 bits adecuada para AES
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            Key key = keyGenerator.generateKey();
            // Alternativamente, una clave que queramos que tenga al menos 16 bytes
            // y nos quedamos con los bytes 0 a 15 = 128 = 16 Bytes x 8 bits
            key = new SecretKeySpec(pass.getBytes("UTF-8"), 0, 16, "AES");
            // Se obtiene un cifrador AES
            Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
            // Se inicializa para encriptacion y se encripta el texto,
            // que debemos pasar como bytes.
            aes.init(Cipher.ENCRYPT_MODE, key);
            byte[] encriptado = aes.doFinal(mensaje.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(encriptado);

        } catch (Exception ex) {
            System.err.println("Error al codificar con AES: " + ex.getMessage());
        }
        return null;

    }

    /**
     * Descodifica una cadena cifrada en AES 128
     *
     * @param mensaje mensaje cifrado
     * @param pass    contraseña para descifrar
     * @return mensaje descifrado
     */
    public String descifrarAES(String mensaje, String pass) {
        try {

            // Generamos una clave de 128 bits adecuada para AES
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            Key key = keyGenerator.generateKey();
            // Alternativamente, una clave que queramos que tenga al menos 16 bytes
            // y nos quedamos con los bytes 0 a 15 = 128 = 16 Bytes x 8 bits
            key = new SecretKeySpec(pass.getBytes(), 0, 16, "AES");
            // Se obtiene un cifrador AES
            Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
            // Se iniciliza el cifrador para desencriptar, con la
            // misma clave y se desencripta
            aes.init(Cipher.DECRYPT_MODE, key);
            byte[] encriptado = Base64.getDecoder().decode(mensaje);
            byte[] desencriptado = aes.doFinal(encriptado);
            // Texto obtenido, igual al original.
            return new String(desencriptado);
        } catch (Exception ex) {
            System.err.println("Error al descodificar con AES: " + ex.getLocalizedMessage());
        }

        return null;
    }

    /**
     * Salva la clave AES codificada en un fichero
     *
     * @param pass    contraseña a lamcenar
     * @param fichero fichero donde se almacenará la clave
     */
    public void salvarClaveAES(String pass, String fichero) {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            Key key = keyGenerator.generateKey();
            // Alternativamente, una clave que queramos que tenga al menos 16 bytes
            // y nos quedamos con los bytes 0 a 15 = 128 = 16 Bytes x 8 bits
            key = new SecretKeySpec(pass.getBytes("UTF-8"), 0, 16, "AES");
            String sal = Base64.getEncoder().encodeToString(key.getEncoded());
            PrintWriter ficheroSalida = new PrintWriter(
                    new FileWriter(fichero));
            ficheroSalida.println(sal);
            ficheroSalida.close();
        } catch (Exception ex) {
            System.err.println("Error al salvar clave AES: " + ex.getLocalizedMessage());
        }
    }

    /**
     * Recupera las claves AES almacenaras en fichero
     *
     * @param fichero donde está almacenada la clave
     * @return
     */
    public String cargarClaveAES(String fichero) {
        try {
            BufferedReader ficheroEntrada = new BufferedReader(
                    new FileReader(fichero));

            String linea = null;
            String sal = "";
            while ((linea = ficheroEntrada.readLine()) != null) {
                sal += linea;
            }
            ficheroEntrada.close();
            byte[] clave = Base64.getDecoder().decode(sal);
            return new String(clave);
        } catch (Exception ex) {
            System.err.println("Error al importar clave AES: " + ex.getLocalizedMessage());
        }
        return null;
    }

    /**
     * Crea una clave AES el propio sistema y la almacena en fichero
     *
     * @param fichero
     */
    public void crearClaveAES(String fichero) {
        try {
            // Generamos una clave de 128 bits adecuada para AES
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            Key key = keyGenerator.generateKey();

            // Se salva y recupera de fichero la clave publica
            String sal = Base64.getEncoder().encodeToString(key.getEncoded());
            PrintWriter ficheroSalida = new PrintWriter(
                    new FileWriter(fichero + "-aes.dat"));
            ficheroSalida.println(sal);
            ficheroSalida.close();
        } catch (Exception ex) {
            System.err.println("Error al crear clave AES: " + ex.getLocalizedMessage());
        }
    }

}
