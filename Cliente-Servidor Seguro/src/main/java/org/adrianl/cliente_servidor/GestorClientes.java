package org.adrianl.cliente_servidor;

import javax.crypto.*;
import javax.net.ssl.SSLSocket;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Base64;


public class GestorClientes extends Thread{

    private SSLSocket cliente;
    private DataOutputStream datoSalida;
    DataInputStream datoEntrada;
    int contador;
    boolean salir = false;
    String id;
    int max = 20;
    Key sessionKey;
    PrivateKey privateKey;
    PublicKey publicKey;
    byte[] sesionCifrada;

    public GestorClientes(SSLSocket cliente){
        id = cliente.getInetAddress()+":"+cliente.getPort();
        this.cliente = cliente;
    }

    @Override
    public void run() {
        if(salir == false){
            try {
                //Instanciar flujos
                datoEntrada = new DataInputStream(cliente.getInputStream());
                datoSalida = new DataOutputStream(cliente.getOutputStream());
                sesion();
                datoEntrada.close();
                datoSalida.close();
            } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException | UnrecoverableKeyException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
                e.printStackTrace();
            }
        }else{
            this.interrupt();
        }
    }

    public void sesion() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        //Cargar clave pública
        String fichero = System.getProperty("user.dir")+ File.separator+"cert"+File.separator+"AlmacenSSL.jks";
        FileInputStream fis = new FileInputStream(fichero);
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(fis, "1234567".toCharArray());
        fis.close();
        String alias = "ClaveSSL";
        Key key = keyStore.getKey(alias, "1234567".toCharArray());
        if(key instanceof PrivateKey){
            Certificate cert = keyStore.getCertificate(alias);
            this.publicKey = cert.getPublicKey();
            this.privateKey = (PrivateKey) key;
        }
        //Recibir clave
        int longitud = this.datoEntrada.readInt();
        byte[] clave = new byte[longitud];
        this.datoEntrada.read(clave);
        this.sesionCifrada = clave;
        //Descifrar clave
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        this.sessionKey = kg.generateKey();
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(Cipher.UNWRAP_MODE, privateKey);
        this.sessionKey = c.unwrap(this.sesionCifrada, "AES", Cipher.SECRET_KEY);
        while(!salir){
            String datoRec = this.descifrar(this.datoEntrada.readUTF());
            System.out.println("Servidor -> recibe del Cliente "+datoRec);
            String datoEnv = "Hola Cliente "+this.contador;
            this.datoSalida.writeUTF(this.cifrar(datoEnv));
            System.out.println("Servidor -> envia al Cliente "+datoEnv);
            contador++;
            if(contador>=max){
                salir = true;
            }else{
                datoSalida.writeUTF(this.cifrar(String.valueOf(this.salir)));
            }
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
