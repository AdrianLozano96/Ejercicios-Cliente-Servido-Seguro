package org.adrianl.cliente_servidor;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class ClienteApp {
    public static void main(String[] args) throws UnrecoverableKeyException, NoSuchPaddingException, IllegalBlockSizeException, CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException, BadPaddingException, InvalidKeyException {
        Cliente cliente = new Cliente();
        cliente.iniciarCliente();
    }
}
