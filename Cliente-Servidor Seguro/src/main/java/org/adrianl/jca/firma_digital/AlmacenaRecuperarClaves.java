package org.adrianl.jca.firma_digital;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class AlmacenaRecuperarClaves {

    public static void almacenarClaves(PrivateKey clavepriv, PublicKey clavepubl) throws IOException {
        //Para almacenar y recuperar las claves públicas y privadas en fichero.
        //Guardar la clave privada: es necesario codificarla en PKCS8 usando la clase PKCS8EncodedKeySpec.
        PKCS8EncodedKeySpec pk8Spec = new PKCS8EncodedKeySpec(clavepriv.getEncoded());
        //Escribir a fichero binario la clave privada.
        FileOutputStream outpriv = new FileOutputStream("clavePrivada");
        outpriv.write(pk8Spec.getEncoded());
        outpriv.close();

        //Para almacenar la clave pública: es necesario codificarla en formato X.509 usando la clase X509EncodedKeySpec.
        X509EncodedKeySpec pkX509 = new X509EncodedKeySpec(clavepubl.getEncoded());
        //Escribir a fichero binario la clave pública.
        FileOutputStream out = new FileOutputStream("clavePublica");
        out.write(pkX509.getEncoded());
        out.close();
    }

    public static void recuperarClaves(PrivateKey clavepriv, PublicKey clavepubl) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        //Para recuperar las claves de los ficheros necesitamos la clase KeyFactory que proporciona métodos
        // para convertir claves de formato criptográfico (PKCS8, X.509) a especificaciones de claves y viceversa.
        //Recuperar la clave privada:   Leemos el fichero.
        FileInputStream in = new FileInputStream("clavePrivada");
        byte[] BufferPriv = new byte[in.available()];   //Definimos el buffer dle tamaño exacto
        in.read(BufferPriv);        //Leemos los bytes
        in.close();
        KeyFactory keyDSApriv = KeyFactory.getInstance("DSA");
        //Recuperamos la clave privada desde datos codificados en PKCS8
        PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(BufferPriv);
        clavepriv = keyDSApriv.generatePrivate(clavePrivadaSpec);

        //Recuperar la clave pública:   Leemos el fichero.
        FileInputStream inpub = new FileInputStream("clavePublica");
        byte[] bufferPub = new byte[inpub.available()];
        inpub.read(bufferPub);
        inpub.close();
        KeyFactory keyDSApub = KeyFactory.getInstance("DSA");
        //Recuperamos la clave pública desde datos codificados en X509.
        X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bufferPub);
        clavepubl = keyDSApub.generatePublic(clavePublicaSpec);
    }

}
