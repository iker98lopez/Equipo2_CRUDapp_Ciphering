package equipo2_crudapp_ciphering;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Logger;

/**
 * This class generates a key pair and generates the files private.key and
 * public.key
 *
 * @author iker lopez carrillo
 */
public class KeyGenerator {

    private static final Logger LOGGER = Logger.getLogger("equipo2_crudapp_ciphering.KeyGenerator");

    /**
     * Generates a new key pair and creates a file to contain each one.
     */
    public void generateKeyPair() {

        KeyPairGenerator keyPairGenerator;
        FileOutputStream fileOutputStream = null;

        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(1024);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // Generates the public key and creates the file to contain it.
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
            fileOutputStream = new FileOutputStream("public.key");
            fileOutputStream.write(x509EncodedKeySpec.getEncoded());
            fileOutputStream.close();

            // Generates the private key and creates the file to contain it
            PKCS8EncodedKeySpec pKCS8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
            fileOutputStream = new FileOutputStream("private.key");
            fileOutputStream.write(pKCS8EncodedKeySpec.getEncoded());
            fileOutputStream.close();
        } catch (IOException | NoSuchAlgorithmException exception) {
            LOGGER.warning("There was an error while trying to generate the keys. " + exception.getMessage());
        } finally {
            try {
                if (fileOutputStream != null) {
                    fileOutputStream.close();
                }
            } catch (IOException exception) {
                LOGGER.warning("There was an error while closing the files. " + exception.getMessage());
            }
        }
    }

    public static void main(String[] args) {
        KeyGenerator keyGenerator = new KeyGenerator();
        keyGenerator.generateKeyPair();
        
        LOGGER.info("Key pair generated successfully");
    }
}
