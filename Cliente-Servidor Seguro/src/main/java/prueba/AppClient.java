package prueba;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class AppClient {
    public static void main(String[] args) {
        MiCliente cliente = new MiCliente();
        try {
            cliente.iniciar();
        } catch (IOException | NoSuchAlgorithmException | UnrecoverableKeyException | CertificateException | KeyStoreException | NoSuchPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }
}
