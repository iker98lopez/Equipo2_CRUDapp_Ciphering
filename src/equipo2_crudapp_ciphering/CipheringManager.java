/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package equipo2_crudapp_ciphering;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
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
    public String hashCipher(String text) {
        
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
    public String cipherText(String text) {
        byte[] encodedMessage = null;
        BufferedReader in = null;
        try {
            in = new BufferedReader(new InputStreamReader(new FileInputStream(new File("public.key"))));
            
            X509EncodedKeySpec spec = new X509EncodedKeySpec(in.readLine().getBytes());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(spec);
            
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            encodedMessage = cipher.doFinal(text.getBytes());
        } catch (IOException exception) {
            LOGGER.warning("There was an error trying to find the private key. " + exception.getMessage());
        } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException exception) {
            LOGGER.warning("There was an error trying to cipher the text. " + exception.getMessage());
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException exception) {
                    LOGGER.warning("There was an error trying to close the key file. " + exception.getMessage());
                }
            }
        }
        return Arrays.toString(encodedMessage);
    }

    /**
     * This method receives a ciphered String, deciphers it and returns it.
     *
     * @param text String to decipher.
     * @return deciphered String.
     */
    public String decipherText(String text) {
        byte[] decodedMessage = null;
        BufferedReader in = null;
        try {
            in = new BufferedReader(new InputStreamReader(new FileInputStream(new File("private.key"))));
            
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(in.readLine().getBytes());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(spec);
            
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            decodedMessage = cipher.doFinal(text.getBytes());
        }  catch (IOException exception) {
            LOGGER.warning("There was an error trying to find the public key. " + exception.getMessage());
        } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException exception) {
            LOGGER.warning("There was an error trying to decipher the text. " + exception.getMessage());
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException exception) {
                    LOGGER.warning("There was an error trying to close the key file. " + exception.getMessage());
                }
            }
        }
        
        return Arrays.toString(decodedMessage);
    }
    
    /**
     * This method converts the ciphered text received to an hexadecimal String.
     * 
     * @param cipheredText text to convert.
     * @return converted text in hexadecimal.
     */
    private String hexadecimalConverter(byte[] cipheredText) {
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
    
    public static void main(String[] args) {
        CipheringManager cipheringManager = new CipheringManager();
        
        String message = "Mensaje";
        LOGGER.info(message);
        
        message = cipheringManager.cipherText(message);
        LOGGER.info(message);
        
        message = cipheringManager.decipherText(message);
        LOGGER.info(message);
        
        String messageHash = cipheringManager.hashCipher(message);
        LOGGER.info(messageHash);
    }
}
