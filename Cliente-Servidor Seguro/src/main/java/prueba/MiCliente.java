package prueba;

import javax.crypto.*;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

public class MiCliente {

    private final int PUERTO = 9696;
    private String direccion;
    private SSLSocket servidor;
    private SSLSocketFactory clientFactory;
    private boolean salir = false;
    DataInputStream datoEntrada = null;
    DataOutputStream datoSalida = null;
    private static final int ESPERAR = 1000;
    private Key sessionKey;
    private PublicKey publicKey;
    private byte[] sesionCifrada;

    public void iniciar() throws IOException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, KeyStoreException, NoSuchPaddingException, IllegalBlockSizeException, InvalidKeyException {
        direccion = InetAddress.getLocalHost().getHostAddress();    // Antes de nada compruebo la direccion
        // Nos conectamos
        String fichero = System.getProperty("user.dir") + File.separator + "cert" + File.separator + "UsuarioAlmacenSSL.jks";
        System.setProperty("javax.net.ssl.trustStore", fichero);
        System.setProperty("javax.net.ssl.trustStorePassword", "0987654");
        this.clientFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();// Me conecto
        this.servidor = (SSLSocket) clientFactory.createSocket(this.direccion, this.PUERTO);
        datoEntrada = new DataInputStream(servidor.getInputStream());
        datoSalida = new DataOutputStream(servidor.getOutputStream());
        System.out.println("Cliente->Conectado al servidor...");
        //Mostrar sesión
        SSLSession sesion = ((SSLSocket) this.servidor).getSession();
        System.out.println("Servidor: " + sesion.getPeerHost());
        System.out.println("Cifrado: " + sesion.getCipherSuite());
        System.out.println("Protocolo: " + sesion.getProtocol());
        System.out.println("IDentificador:" + new BigInteger(sesion.getId()));
        System.out.println("Creación de la sesión: " + sesion.getCreationTime());
        X509Certificate certificado = (X509Certificate) sesion.getPeerCertificates()[0];
        System.out.println("Propietario : " + certificado.getSubjectDN());
        System.out.println("Algoritmo: " + certificado.getSigAlgName());
        System.out.println("Tipo: " + certificado.getType());
        System.out.println("Emisor: " + certificado.getIssuerDN());
        System.out.println("Número Serie: " + certificado.getSerialNumber());
        sesion();   //enviar Clave()
        procesar(); // Procesamos
        //Cerramos
        // Me desconecto
        servidor.close();
        datoEntrada.close();
        datoSalida.close();
        System.out.println("Cliente->Desconectado");
    }


    private void sesion() throws NoSuchAlgorithmException, IOException, KeyStoreException, CertificateException, UnrecoverableKeyException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
        //- Generamos la clave de sesion
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        this.sessionKey = kg.generateKey();
        //- Recibimos la clave pública
        String fichero = System.getProperty("user.dir") + File.separator + "cert" + File.separator + "UsuarioAlmacenSSL.jks";
        FileInputStream fis = new FileInputStream(fichero);
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(fis, "0987654".toCharArray());
        fis.close();
        String alias = "ClaveSSL";
        Key key = keystore.getKey(alias, "0987654".toCharArray());
        // Obtenemos el certificado
        Certificate cert = keystore.getCertificate(alias);
        // Obtenemos la clave pública
        this.publicKey = cert.getPublicKey();
        //- Ciframos la clave de sesion
        //se encripta la clave secreta con la clave pública
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(Cipher.WRAP_MODE, this.publicKey);
        this.sesionCifrada = c.wrap(this.sessionKey);
        //- Enviamos la clave
        // la pasamos cifrada pero como Code64 para que vaya como un string
        byte[] clave = this.sesionCifrada;
        System.out.println("Cliente->Enviado clave de sesion");
        // Mandamos longitud y clave
        this.datoSalida.writeInt(clave.length);
        this.datoSalida.write(clave);
        System.out.println("Cliente->Clave de sesion enviada " + clave.toString());
    }

    private String cifrar(String mensaje) {
        try {
            Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, this.sessionKey);
            byte[] encriptado = c.doFinal(mensaje.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(encriptado);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | UnsupportedEncodingException | IllegalBlockSizeException | BadPaddingException ex) {
            System.err.println("ServidorGC->ERROR: cifrar mensaje " + ex.getMessage());
        }
        return null;
    }

    private String descifrar(String mensaje) {
        try {
            Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, this.sessionKey);
            byte[] encriptado = Base64.getDecoder().decode(mensaje);
            byte[] desencriptado = c.doFinal(encriptado);
            // Texto obtenido, igual al original.
            return new String(desencriptado);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException ex) {
            System.err.println("ServidorGC->ERROR: descifrar mensaje " + ex.getMessage());
        }
        return null;
    }

    private void procesar() throws IOException {
        // Ciclamos hasta que salgamos. Escuchamos hasta aburrirnos, es decir, hasta que salgamos
        while (!salir) {
            //- Envaimos el mensaje
            System.out.println("Cliente->Enviado mensaje");
            String dato = "Mensaje: " + Instant.now().getEpochSecond();
            this.datoSalida.writeUTF(this.cifrar(dato));
            System.out.println("Cliente->Mensaje enviado a Servidor: " + dato);
            //- Recibimos la respuesta
            System.out.println("Cliente->Recepción de mensajes");
            String datoIn = this.descifrar(this.datoEntrada.readUTF());
            System.out.println("Cliente->Mensaje recibido: " + datoIn);
            //- Vemos si salimos
            System.out.println("Cliente->¿Salir?");
            this.salir = Boolean.parseBoolean(this.descifrar(this.datoEntrada.readUTF()));
            System.out.println("Cliente->Salir: " + this.salir);
            //esperar();  // esperamos
            //Thread.sleep(this.ESPERAR);
        }
    }

}