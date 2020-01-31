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
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
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
public class ClientCipher {

    /**
     * Logger to show error messages and exceptions.
     */
    private static final Logger LOGGER = Logger.getLogger("equipo2_crudapp_ciphering.HashCipher");

    /**
     * This method receives a String and returns it ciphered.
     *
     * @param text String to cipher.
     * @return ciphered String.
     */
    public static byte[] cipherText(byte[] text) {
        byte[] encodedMessage = null;
        try {
            byte fileKey[] = fileReader("public.key");

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(fileKey);
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            encodedMessage = cipher.doFinal(text);
        } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException exception) {
            LOGGER.warning("There was an error trying to cipher the text. " + exception.getClass() + " " + exception.getMessage());
        }

        return encodedMessage;
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
            byte[] buffer = new byte[256];
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
