import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.xml.bind.DatatypeConverter;

public class HashSign {

	
	public static void writeToFile(String path, byte[] key) throws IOException {
		File f = new File(path);
		f.getParentFile().mkdirs();

		FileOutputStream fos = new FileOutputStream(f);
		fos.write(key);
		fos.flush();
		fos.close();
	}
	
	public static PrivateKey getPrivate() throws Exception {
		FileInputStream keyfis = new FileInputStream("src/PrivateKey");
		byte[] encKey = new byte[keyfis.available()];  
		keyfis.read(encKey);

		keyfis.close();
		
		PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(encKey);
		KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
		
		PrivateKey pubKey =
				keyFactory.generatePrivate(privKeySpec);
		
		return pubKey;
	}
	
	public static void Sign() throws Exception {
        // ------------------
        InputStream is = new FileInputStream("src/text.txt");
        BufferedReader buf = new BufferedReader(new InputStreamReader(is));

        String line = buf.readLine();
        StringBuilder sb = new StringBuilder();

        while (line != null) {
            sb.append(line).append("\n");
            line = buf.readLine();
        }

        String fileAsString = sb.toString();

        // ------------------- Hashing
	    
	    MessageDigest md = MessageDigest.getInstance("MD5");
	    md.update(fileAsString.getBytes());
	    byte[] digest = md.digest();
	    String myHash = DatatypeConverter
	      .printHexBinary(digest).toUpperCase();
	    
	    PrintWriter out = new PrintWriter("src/Hashed.txt");
	    out.println(myHash);
	    out.close();
	    
		Signature dsa = Signature.getInstance("SHA1withDSA", "SUN"); 
		
		PrivateKey privateKey = getPrivate();
		
		dsa.initSign(privateKey);
		
		
        // ------------------ Signing
		
		FileInputStream fis = new FileInputStream("src/Hashed.txt");
		BufferedInputStream bufin = new BufferedInputStream(fis);
		byte[] buffer = new byte[1024];
		int len;
		while ((len = bufin.read(buffer)) >= 0) {
		    dsa.update(buffer, 0, len);
		};
		bufin.close();

        // ------------------- Export Signed and Signature
        
		byte[] realSig = dsa.sign();
		
		FileOutputStream sigfos = new FileOutputStream("src/signature");
		sigfos.write(realSig);
		sigfos.close();
		System.out.println("Signature file has been created");
		
	}
	
	public static void Verify() throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, SignatureException{
		
		//read publickey
		FileInputStream keyfis = new FileInputStream("src/PublicKey");
		byte[] encKey = new byte[keyfis.available()];  
		keyfis.read(encKey);

		keyfis.close();
		
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
		KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
		
		PublicKey pubKey =
			    keyFactory.generatePublic(pubKeySpec);
		

		//read hashed file
		FileInputStream sigfis = new FileInputStream("src/signature");
		byte[] sigToVerify = new byte[sigfis.available()]; 
		sigfis.read(sigToVerify);
		sigfis.close();
		
		
		//Init signature
		
		Signature sig = Signature.getInstance("SHA1withDSA", "SUN");
		sig.initVerify(pubKey);
		
		FileInputStream datafis = new FileInputStream("src/decrypted_File.txt");
		BufferedInputStream bufin = new BufferedInputStream(datafis);

		byte[] buffer = new byte[1024];
		int len;
		while (bufin.available() != 0) {
		    len = bufin.read(buffer);
		    sig.update(buffer, 0, len);
		};

		bufin.close();
		
		boolean verifies = sig.verify(sigToVerify);

		System.out.println("signature verifies: " + verifies);
		
	}
	
	public static void main (String args[]) throws Exception{
		
		if (args[0].equals("sign")){
			Sign();
		}else if (args[0].equals("verify")){
			Verify();
		}else{
			System.out.println("There is an error");
		}

        
	}
}
