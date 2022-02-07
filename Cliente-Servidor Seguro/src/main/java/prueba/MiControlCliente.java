package prueba;

import javax.crypto.*;
import javax.net.ssl.SSLSocket;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Base64;

public class MiControlCliente extends Thread {

    private SSLSocket cliente = null;
    DataInputStream controlEntrada = null;
    DataOutputStream controlSalida = null;
    private int contador = 1;
    private boolean salir = false;
    String ID;
    private static final int MAX = 20;
    private Key sessionKey = null;
    private PrivateKey privateKey = null;
    private byte[] sesionCifrada = null;
    private PublicKey publicKey;

    public MiControlCliente(SSLSocket cliente) {
        this.cliente = cliente;
        this.contador = 1;
        this.salir = false;
        this.ID = cliente.getInetAddress() + ":" + cliente.getPort();
    }

    @Override
    public void run() {
        if (salir == false) {   // Trabajamos con ella
            try {
                //crearFlujosES();
                controlEntrada = new DataInputStream(cliente.getInputStream());
                controlSalida = new DataOutputStream(cliente.getOutputStream());
                sesion();   // Datos de la sesion
                tratarConexion();   // Tratamos la conexion
                controlEntrada.close();
                controlSalida.close();
            } catch (IOException | UnrecoverableKeyException | CertificateException | KeyStoreException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
                e.printStackTrace();
            }
        } else { this.interrupt(); }  // Me interrumpo y no trabajo
    }


    private void sesion() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, NoSuchPaddingException, InvalidKeyException {
        //cargarClaves(); // cargamos la clave pública
        String fichero = System.getProperty("user.dir") + File.separator + "cert" + File.separator + "AlmacenSSL.jks";
        FileInputStream fis = new FileInputStream(fichero);
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(fis, "1234567".toCharArray());
        fis.close();
        String alias = "ClaveSSL";
        Key key = keystore.getKey(alias, "1234567".toCharArray());
        if (key instanceof PrivateKey) {
            Certificate cert = keystore.getCertificate(alias);  // Obtenemos el certificado
            this.publicKey = cert.getPublicKey();   // Obtenemos la clave pública
            this.privateKey = (PrivateKey) key; // Casteamos y almacenamos la clave
        }
        //recibirClave(); // recibimos la clave de sesion
        System.out.println("ServidorGC->Recibiendo clave de sesión");
        int l = this.controlEntrada.readInt();  // leemos la longitid
        byte[] clave = new byte[l];
        this.controlEntrada.read(clave);
        System.out.println("ServidorGC->Clave de sesión recibida de [" + this.ID + "]: " + clave.toString());
        this.sesionCifrada = clave;
        //descifrarClave();   //desciframos la clave
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        this.sessionKey = kg.generateKey();
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(Cipher.UNWRAP_MODE, privateKey);
        this.sessionKey = c.unwrap(this.sesionCifrada, "AES", Cipher.SECRET_KEY);
    }


    private void tratarConexion() throws IOException {
        while (!salir) {    // Escuchamos hasta aburrirnos, es decir, hasta que salgamos
            //recibir();  //Recibimos un mensaje
            String dato = this.descifrar(this.controlEntrada.readUTF());
            System.out.println("ServidorGC->Mensaje recibido de [" + this.ID + "]: " + dato);
            //enviar();   // Devolvemos una respuesta
            String datOut = "Mensaje de reespuesta num: " + this.contador;
            this.controlSalida.writeUTF(this.cifrar(datOut));
            System.out.println("ServidorGC->Mensaje enviado a [" + this.ID + "]: " + datOut);
            this.contador++;    // Aumentamos el contador
            if (!salir) { salir(); }    // Le indicamos si sale
        }
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


    private void salir() {
        if (this.contador >= this.MAX) {
            this.salir = true;
        } else { this.salir = false; }  // No es necssario pero es un ejemplo didáctico y quiero que quede claro
        try {   // Envamos la respuesta
            System.out.println("ServidorGC->Enviar si salir");
            String salida = String.valueOf(this.salir);
            controlSalida.writeUTF(this.cifrar(salida));
        } catch (IOException ex) {
            System.err.println("ServidorGC->ERROR: al enviar ID de Cliente " + ex.getMessage());
        }
    }

}