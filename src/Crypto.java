import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Crypto {
    private static PrivateKey privateKey;
    private static PublicKey publicKey;
    
	private Cipher cipher;

	public Crypto() throws NoSuchAlgorithmException, NoSuchPaddingException {
		this.cipher = Cipher.getInstance("RSA");
	}
    
		public PublicKey getPublic() throws Exception {
			byte[] keyBytes = Files.readAllBytes(new File("KeyPair/PublicKey").toPath());
			X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePublic(spec);
		}
		
		public PrivateKey getPrivate() throws Exception {
			byte[] keyBytes = Files.readAllBytes(new File("KeyPair/PrivateKey").toPath());
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePrivate(spec);
		}
	   
		public void encryptFile(byte[] input, File output, PrivateKey key) 
				throws IOException, GeneralSecurityException {
				this.cipher.init(Cipher.ENCRYPT_MODE, key);
				writeToFile(output, this.cipher.doFinal(input));
				System.out.println("File encrypted");
			}
	 
		public void decryptFile(byte[] input, File output, PublicKey key) 
				throws IOException, GeneralSecurityException {
				this.cipher.init(Cipher.DECRYPT_MODE, key);
				writeToFile(output, this.cipher.doFinal(input));
				System.out.println("File decrypted");
			}
	   
		private void writeToFile(File output, byte[] toWrite)
				throws IllegalBlockSizeException, BadPaddingException, IOException {
			FileOutputStream fos = new FileOutputStream(output);
			fos.write(toWrite);
			fos.flush();
			fos.close();
		}
		
		public byte[] getFileInBytes(File f) throws IOException {
			FileInputStream fis = new FileInputStream(f);
			byte[] fbytes = new byte[(int) f.length()];
			fis.read(fbytes);
			fis.close();
			return fbytes;
		}
	   
		public static void main(String[] args) throws Exception {
			Crypto ac = new Crypto();
			PrivateKey privateKey = ac.getPrivate();
			PublicKey publicKey = ac.getPublic();

			if(args[0].equals("encrypt")){
				//Encrypt File
				ac.encryptFile(ac.getFileInBytes(new File("src/Hashed.txt")), 
						new File("src/encrypted_File.txt"),privateKey);
			}
			else if (args[0].equals("decrypt")){
				//Decrypt File
				ac.decryptFile(ac.getFileInBytes(new File("src/encrypted_File.txt")),
						new File("src/decrypted_File.txt"), publicKey);
			}else{
				System.out.println("error");
			}

			

		}

}
