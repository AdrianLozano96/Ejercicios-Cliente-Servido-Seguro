package org.adrianl.cliente_servidor;

import javax.crypto.*;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.security.cert.Certificate;
import java.io.*;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Base64;

public class Cliente {

    private SSLSocket servidor;
    private SSLSocketFactory clientFactory;
    private boolean salir = false;
    private int puerto = 9696;
    private String ip;
    private DataOutputStream datoSalida = null;
    private DataInputStream datoEntrada = null;
    private Key sessionKey;
    private PublicKey publicKey;
    private byte[] sesionCifrada;

    public void iniciarCliente(){
        try {
            iniciarConexion();
            compartirInfo();
            servidor.close();
            datoEntrada.close();
            datoSalida.close();
        } catch (IOException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException | CertificateException | NoSuchPaddingException | IllegalBlockSizeException | InvalidKeyException | BadPaddingException e) {
            e.printStackTrace();
        }
    }

    public void iniciarConexion() throws IOException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchPaddingException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException {
        ip = InetAddress.getLocalHost().getHostAddress();
        String fichero = System.getProperty("user.dir")+ File.separator+"cert"+File.separator+"UsuarioAlmacenSSL.jks";
        System.setProperty("javax.net.ssl.trustStore",fichero);
        System.setProperty("javax.net.ssl.trustStorePassword","0987654");
        //Conexión
        this.clientFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        this.servidor = (SSLSocket) clientFactory.createSocket(this.ip, this.puerto);
        datoSalida = new DataOutputStream(servidor.getOutputStream());
        datoEntrada = new DataInputStream(servidor.getInputStream());
        //Mostrar Sesion
        SSLSession sesion = ((SSLSocket)this.servidor).getSession();
        System.out.println("Servidor: " + sesion.getPeerHost());
        System.out.println("Cifrado: " + sesion.getCipherSuite());
        X509Certificate certificado = (X509Certificate) sesion.getPeerCertificates()[0];
        System.out.println("Propietario : " + certificado.getSubjectDN());
        System.out.println("Algoritmo: " + certificado.getSigAlgName());
        System.out.println("Emisor: " + certificado.getIssuerDN());
        //- Crear Sesión
        KeyGenerator kg = KeyGenerator.getInstance("AES");  //Genera clave de sesión AES
        kg.init(128);
        this.sessionKey = kg.generateKey();
        FileInputStream fis = new FileInputStream(fichero); //Cargar claves
        //char[] password;
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(fis, "0987654".toCharArray());    //Cargo la contraseña
        fis.close();
        String alias = "ClaveSSL";
        Key key = keystore.getKey(alias,"0987654".toCharArray());   //Obtengo la clave completa UsuarioAlmacenSSL.jks
        Certificate cert = keystore.getCertificate(alias);  //Obtengo el certificado
        this.publicKey = cert.getPublicKey(); //Le asigno a mi pk la pk del certificado
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding"); //Cifra la clave encriptando la clave secreta con la clave pública
        c.init(Cipher.WRAP_MODE, this.publicKey);
        this.sesionCifrada = c.wrap(this.sessionKey);

        byte[] clave = this.sesionCifrada;  //Se envia la clave
        this.datoSalida.writeInt(clave.length);
        this.datoSalida.write(clave);   //Se pas cifrada con Code64 y se manda la longitud y la clave


    }

    public void compartirInfo() throws NoSuchPaddingException, IOException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        while(!salir) {
            String mensajEnviar = "Hola Servidor " + LocalDateTime.now();
            datoSalida.writeUTF(cifrar(mensajEnviar));
            System.out.println("Cliente -> envia al Servidor: "+ mensajEnviar);
            String mensajeRecibido = descifrar(datoEntrada.readUTF());
            System.out.println("Cliente -> Recibe del Servidor: "+mensajeRecibido);
            this.salir = Boolean.parseBoolean(descifrar(datoEntrada.readUTF()));
            System.out.println("Salir es "+salir);
        }
    }

    public String cifrar(String msg) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, this.sessionKey);
        byte[] encriptado = c.doFinal(msg.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encriptado);
    }

    public String descifrar(String msg) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, this.sessionKey);
        byte[] encriptado = Base64.getDecoder().decode(msg);
        byte[] desencriptado = c.doFinal(encriptado);
        return new String(desencriptado);
    }
}