/**
 * La firma digital constará de una clave privada que generará el mensaje y de
 * una pública que lo verificará.
 * 
 */
package org.adrianl.jca.otros;
import java.security.*;
import java.util.logging.Level;
import java.util.logging.Logger;
/**
 *
 * @author faranzabe
 */
public class Asimetrica_1 {

    /**
     * @param args the command line arguments
     * 
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
            PublicKey  clavepubl = par.getPublic();
            
            //Firmamos con la clave privada el mensaje.
            //Al especificar el nombre del algoritmo de firma se debe especificar, también,
            //el nombre del algoritmo resumen utilizado por el algoritmo de firma.
            //Tendremos dos:
            //  - SHAwithDSA --> firma con DSA resumen con SHA.
            //  - MD5withRSA --> firma con RSA resumen con MD5.
            Signature dsa = Signature.getInstance("SHA1withDSA");
            dsa.initSign(clavepriv);
            
            
            String mensaje = "Mensaje que será firmado";
            dsa.update(mensaje.getBytes());
            
            byte []firma = dsa.sign(); //Mensaje firmado.
            
            
            //El receptor del mensaje, verifica con clave pública 
            //el mensaje firmado.
            Signature verifica_dsa = Signature.getInstance("SHA1withDSA");
            verifica_dsa.initVerify(clavepubl);
            
            //mensaje = "Otra cosa";
            verifica_dsa.update(mensaje.getBytes());
            boolean check = verifica_dsa.verify(firma);
            if (check) System.out.println("OK");
            else       System.out.println("Firma no verificada");
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            Logger.getLogger(Asimetrica_1.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(Asimetrica_1.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}