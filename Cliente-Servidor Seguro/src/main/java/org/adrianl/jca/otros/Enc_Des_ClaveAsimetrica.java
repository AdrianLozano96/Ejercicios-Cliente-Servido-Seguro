/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.adrianl.jca.otros;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


/**
 *
 * @author faranzabe
 */
public class Enc_Des_ClaveAsimetrica {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException  {

        //Se crean el par de claves públicas y privada.
        KeyPairGenerator KeyGen = KeyPairGenerator.getInstance("RSA");
        KeyGen.initialize(1024);
        KeyPair par = KeyGen.generateKeyPair();
        PrivateKey clavepriv = par.getPrivate();
        PublicKey clavepubl = par.getPublic();

        //Ciframos el texto con la clave secreta.
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(Cipher.ENCRYPT_MODE, clavepubl);
        String mensaje = "Hola DAM2, qué tal?";
        byte[] TextoPlano = mensaje.getBytes();
        byte[] TextoCifrado = c.doFinal(TextoPlano);
        System.out.println("Encriptado: " + new String(TextoCifrado));

        //Desciframos el texto con la clave desenvuelta.
        Cipher c2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c2.init(Cipher.DECRYPT_MODE, clavepriv);
        byte []TextoDescifrado = c2.doFinal(TextoCifrado);
        System.out.println("Desencriptado: " + new String(TextoDescifrado));
    }

}
