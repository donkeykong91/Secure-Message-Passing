import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;

import javax.xml.bind.DatatypeConverter;

public class Main {

	public static void main(String[] args) {
		
		Path file = Paths.get("senderPubAndPrivKeys.txt"), file2 = Paths.get("receiverPubAndPrivKeys.txt");
		
		createRsaKeys(file);
		createRsaKeys(file2);
		Sender sender = new Sender();
		sender.init();
		Receiver receiver = new Receiver();
		receiver.init();
	}
	
	static void createRsaKeys(Path file)
	{
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(1024);
			KeyPair keyPair = keyGen.generateKeyPair();

			PublicKey publicKey = keyPair.getPublic();
			PrivateKey privateKey = keyPair.getPrivate();
			
			List<String> lines = Arrays.asList(DatatypeConverter.printHexBinary(publicKey.getEncoded()), 
											   DatatypeConverter.printHexBinary(privateKey.getEncoded()));
			Files.write(file, lines);
			
		} catch (NoSuchAlgorithmException | IOException e) {
			e.printStackTrace();
		}
	}
}
