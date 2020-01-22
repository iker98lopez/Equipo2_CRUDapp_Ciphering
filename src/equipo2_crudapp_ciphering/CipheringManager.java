/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package equipo2_crudapp_ciphering;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * This class contains methods to create hashings, ciphering and deciphering.
 *
 * @author iker lopez carrillo
 */
public class CipheringManager {

    private static final Logger LOGGER = Logger.getLogger("equipo2_crudapp_ciphering.HashCipher");

    /**
     * Generates a hashing from the String received and returns it.
     *
     * @param text String to be ciphered.
     * @return hashing of the text received.
     */
    public static String hashCipher(String text) {

        MessageDigest messageDigest;
        byte hash[] = null;

        try {
            byte dataBytes[] = text.getBytes();

            messageDigest = MessageDigest.getInstance("MD5");
            messageDigest.update(dataBytes);

            hash = messageDigest.digest();
        } catch (NoSuchAlgorithmException exception) {
            LOGGER.warning("There was an error while ciphering. " + exception.getMessage());
        }

        return hexadecimalConverter(hash);
    }

    /**
     * This method receives a String and returns it ciphered.
     *
     * @param text String to cipher.
     * @return ciphered String.
     */
    public static byte[] cipherText(String text) {
        byte[] encodedMessage = null;
        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(fileReader("public.key"));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(spec);

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            encodedMessage = cipher.doFinal(text.getBytes());
        } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException exception) {
            LOGGER.warning("There was an error trying to cipher the text. " + exception.getClass() + " " + exception.getMessage());
        }
        return encodedMessage;
    }

    /**
     * This method receives a ciphered String, deciphers it and returns it.
     *
     * @param text String to decipher.
     * @return deciphered String.
     */
    public static byte[] decipherText(byte[] text) {
        byte[] decodedMessage = null;
        try {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(fileReader("private.key"));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(spec);

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            decodedMessage = cipher.doFinal(text);
        } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException exception) {
            LOGGER.warning("There was an error trying to decipher the text. " + exception.getClass() + " " + exception.getMessage());
        }

        return decodedMessage;
    }

    /**
     * This method converts the ciphered text received to an hexadecimal String.
     *
     * @param cipheredText text to convert.
     * @return converted text in hexadecimal.
     */
    private static String hexadecimalConverter(byte[] cipheredText) {
        String HEX = "";
        for (int i = 0; i < cipheredText.length; i++) {
            String h = Integer.toHexString(cipheredText[i] & 0xFF);
            if (h.length() == 1) {
                HEX += "0";
            }
            HEX += h;
        }
        return HEX.toUpperCase();
    }

    /**
     * This method reads the file in the path it receives and returns it as a
     * byte array.
     *
     * @param path Path of the file.
     * @return Byte array with the contents of the file.
     */
    public static byte[] fileReader(String path) {
        File file = new File(path);
        ByteArrayOutputStream out = null;
        InputStream in = null;

        try {
            byte[] buffer = new byte[4096];
            out = new ByteArrayOutputStream();
            in = new FileInputStream(file);
            int read = 0;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
        } catch (IOException exception) {
            LOGGER.warning("There was an error trying to read the key file. " + exception.getMessage());
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException exception) {
                    LOGGER.warning("There was an error trying to close the key file. " + exception.getMessage());
                }
            }
            if (out != null) {
                try {
                    out.close();
                } catch (IOException exception) {
                    LOGGER.warning("There was an error trying to close the key file. " + exception.getMessage());
                }
            }
        }

        return out.toByteArray();
    }
}
