
import javax.crypto.Cipher;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import java.security.Key;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.security.InvalidKeyException;

public class lab {

    private static String algorithm = "DESede";
    private static Key key = null;
    private static Cipher cipher = null;

    private static void setUp() throws Exception {
        key = KeyGenerator.getInstance(algorithm).generateKey();
        cipher = Cipher.getInstance(algorithm);
    }

    public static void main(String[] args) throws Exception {
        setUp();

        // ------------------
        InputStream is = new FileInputStream("text.txt");
        BufferedReader buf = new BufferedReader(new InputStreamReader(is));

        String line = buf.readLine();
        StringBuilder sb = new StringBuilder();

        while (line != null) {
            sb.append(line).append("\n");
            line = buf.readLine();
        }

        String fileAsString = sb.toString();

        // -------------------
        // Encryption//
        byte[] encryptionBytes = null;
        System.out.println("Entered: " + fileAsString);
        encryptionBytes = encrypt(fileAsString);

        FileOutputStream stream = new FileOutputStream("encrypted.enc");
        try {
            stream.write(encryptionBytes);
        } finally {
            stream.close();
        }

        // -------------------
        // Decryption//

        byte[] array = Files.readAllBytes(new File("encrypted.enc").toPath());

        // -------------------
        System.out.println("Recovered: " + decrypt(array));
    }

    private static byte[] encrypt(String input)
            throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] inputBytes = input.getBytes();
        return cipher.doFinal(inputBytes);
    }

    private static String decrypt(byte[] encryptionBytes)
            throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] recoveredBytes = cipher.doFinal(encryptionBytes);
        String recovered = new String(recoveredBytes);
        return recovered;
    }
}
