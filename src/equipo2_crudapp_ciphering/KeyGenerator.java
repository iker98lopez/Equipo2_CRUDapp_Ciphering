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
import javafx.application.Application;
import static javafx.application.Application.launch;
import javafx.stage.Stage;

/**
 * This class generates a key pair and generates the files private.key and
 * public.key
 *
 * @author iker lopez carrillo
 */
public class KeyGenerator extends Application {

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

    /**
     * Main function of the class. It generates a new key pair and shows a
     * message on the logger.
     *
     * @param args the command line arguments.
     */
    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) throws Exception {
        KeyGenerator keyGenerator = new KeyGenerator();
        keyGenerator.generateKeyPair();

        String password = "abcd*1234";
        FileOutputStream fileOutputStream = new FileOutputStream("credentials.dat");
        fileOutputStream.write(ClientCipher.cipherText(password.getBytes()));
        fileOutputStream.close();

        LOGGER.info("Key pair generated successfully");

        System.exit(0);
    }
}
