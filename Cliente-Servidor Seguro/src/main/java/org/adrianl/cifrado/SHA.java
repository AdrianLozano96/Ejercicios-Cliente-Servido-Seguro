package org.adrianl.cifrado;

import java.security.MessageDigest;

public class SHA {

    /**
     * Codifica a cadena en SHA 256
     *
     * @param cadena
     * @return
     */
    public String SHA256(String cadena) {
        MessageDigest md = null;
        byte[] hash = null;
        // Llamamos a la función de hash de java
        try {
            md = MessageDigest.getInstance("SHA-256");
            hash = md.digest(cadena.getBytes("UTF-8"));
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return convertToHex(hash);
    }

    /**
     * Converts the given byte[] to a hex string.
     *
     * @param raw the byte[] to convert
     * @return the string the given byte[] represents
     */
    private String convertToHex(byte[] raw) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < raw.length; i++) {
            sb.append(Integer.toString((raw[i] & 0xff) + 0x100, 16).substring(1));
        }
        return sb.toString();
    }

}
