/**
 * Vamos a ver como almacenar las claves públicas y privadas en disco. De esta
 * manera se generarán una vez para cada extremo y podrán ser utilizadas cuando
 * sea necesario.
 */
package org.adrianl.jca.otros;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author faranzabe
 */
public class Arch_Recuperar_claves_asimétricas {

    /**
     * Almacenar la clave privada en disco. Será necesario codificarla en
     * formato PKCS8 usando la clave PKCS8EncodedKeySec.
     */
    static void archivar_clave_privada(String nom_fichero, PrivateKey clavepriv) {
        FileOutputStream outpriv = null;
        try {
            PKCS8EncodedKeySpec pk8Spec = new PKCS8EncodedKeySpec(clavepriv.getEncoded());
            //Escribir a fichero binario la clave privada.
            outpriv = new FileOutputStream(nom_fichero);
            outpriv.write(pk8Spec.getEncoded());
            outpriv.close();

        } catch (FileNotFoundException ex) {
            Logger.getLogger(Arch_Recuperar_claves_asimétricas.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Arch_Recuperar_claves_asimétricas.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                outpriv.close();
            } catch (IOException ex) {
                Logger.getLogger(Arch_Recuperar_claves_asimétricas.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    /**
     * Para almacenar la clave pública es necesario codificarla con el formato
     * X.509 usando X509EncodedKeySpec.
     */
    static void archivar_clave_publica(String nom_fichero, PublicKey clavepubl) {
        FileOutputStream out = null;
        try {
            X509EncodedKeySpec pkX509 = new X509EncodedKeySpec(clavepubl.getEncoded());
            //Escribir a fichero binario la clave pública.
            out = new FileOutputStream(nom_fichero);
            out.write(pkX509.getEncoded());
            out.close();

        } catch (FileNotFoundException ex) {
            Logger.getLogger(Arch_Recuperar_claves_asimétricas.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Arch_Recuperar_claves_asimétricas.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Para recuperar las claves de los ficheros necesitamos la clase KeyFactory
     * que proporciona métodos para conertir claves de formato criptográfico
     * (PKCS8, X509) a especificaciones de claves y viceversa.
     */
    /**
     * Recuperar la clave privada del fichero "Clave.privada". Es necesario
     * crear con KeyFactory una instancia del algoritmo DSA (el mismo que se usó
     * para generar el par original).
     */
    static PrivateKey Recuperar_clave_privada(String nom_fichero) {
        FileInputStream in = null;
        PrivateKey cp = null;
        byte BufferPriv[];

        try {

            in = new FileInputStream(nom_fichero);
            BufferPriv = new byte[in.available()];//Definimos el buffer dle tamaño exacto
            in.read(BufferPriv);        //Leemos los bytes
            in.close();

            KeyFactory keyDSA = KeyFactory.getInstance("DSA");
            //Recuperamos la clave privada desde datos codificados en PKCS8
            PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(BufferPriv);
            cp = keyDSA.generatePrivate(clavePrivadaSpec);

        } catch (FileNotFoundException ex) {
            Logger.getLogger(Arch_Recuperar_claves_asimétricas.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Arch_Recuperar_claves_asimétricas.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Arch_Recuperar_claves_asimétricas.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(Arch_Recuperar_claves_asimétricas.class.getName()).log(Level.SEVERE, null, ex);
        }
        return cp;
    }

    /**
     * Para recuperar la clave pública almacenada en el fichero.
     */
    static PublicKey Recuperar_clave_publica(String nom_fichero) {
        FileInputStream inpub = null;
        PublicKey pk = null;

        try {
            //Leemos el fichero.
            inpub = new FileInputStream(nom_fichero);
            byte[] bufferPub = new byte[inpub.available()];
            inpub.read(bufferPub);
            inpub.close();

            KeyFactory keyDSA = KeyFactory.getInstance("DSA");
            //Recuperamos la clave pública desde datos codificados en X509.
            X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bufferPub);
            pk = keyDSA.generatePublic(clavePublicaSpec);

        } catch (FileNotFoundException ex) {
            Logger.getLogger(Arch_Recuperar_claves_asimétricas.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Arch_Recuperar_claves_asimétricas.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException ex) {
            Logger.getLogger(Arch_Recuperar_claves_asimétricas.class.getName()).log(Level.SEVERE, null, ex);
        }

        return pk;
    }

    /**
     * ********************************************************************
     * ****************** Programa Principal ******************************
     * ********************************************************************
     */
    public static void main(String[] args) {
        try {
            //La clase KeyPairGenerator nos permite gernerar el par de claves.
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
            //Se inicia el generador de claves. Se usa el método initialize y le
            //pasamos dos argumentos, el tamaño de la clave y un generador de números 
            //aleatorios.
            //  - El tamaño de un generador de claves DSA (en bits) estará entre 512 y 1024
            //    En cualquier caso múltiplos de 64, en caso contrario da error.
            //  - Como generador de números aleatorios podemos usar una instancia de
            //    SecureRandom.
            SecureRandom numero = SecureRandom.getInstance("SHA1PRNG");
            keyGen.initialize(1024, numero);

            //Creamos el par de claves (privada y pública).
            KeyPair par = keyGen.generateKeyPair();
            PrivateKey clavepriv = par.getPrivate();
            PublicKey clavepubl = par.getPublic();

            System.out.println("Privada almacenada: " + clavepriv.toString());
            System.out.println("Pública almacenada: " + clavepubl.toString());

            //Almacenamos ambas.
            archivar_clave_privada("clave.privada", clavepriv);
            archivar_clave_publica("clave.publica", clavepubl);

            System.out.println("Privada recuperada: " + Recuperar_clave_privada("clave.privada").toString());
            System.out.println("Publica recuperada: " + Recuperar_clave_publica("clave.publica").toString());

            //Las recuperamos.
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Arch_Recuperar_claves_asimétricas.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
