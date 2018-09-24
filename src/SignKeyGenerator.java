import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;


// https://docs.oracle.com/javase/tutorial/security/apisign/step2.html//

public class SignKeyGenerator {
	
	public static void writeToFile(String path, byte[] key) throws IOException {
		File f = new File(path);
		f.getParentFile().mkdirs();

		FileOutputStream fos = new FileOutputStream(f);
		fos.write(key);
		fos.flush();
		fos.close();
	}
	
	public static void main (String args[]) throws NoSuchAlgorithmException, NoSuchProviderException, IOException{
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
		
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
		keyGen.initialize(1024, random);
		
		KeyPair pair = keyGen.generateKeyPair();
		PrivateKey priv = pair.getPrivate();
		PublicKey pub = pair.getPublic();
		
		writeToFile("src/PrivateKey", priv.getEncoded());
		writeToFile("src/PublicKey", pub.getEncoded());
		
		System.out.println("PrivateKey and PublicKey has been created");
		
	}
	
	
}
