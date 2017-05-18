import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

public class Sender {

	public void init() {
		
		String path = "sendingMessage.txt", path2 = "cypheredMessage.txt", path3 = "senderPubAndPrivKeys.txt", path4 = "receiverPubAndPrivKeys.txt";
		
		try(BufferedReader reader = Files.newBufferedReader(Paths.get(path));
			BufferedWriter writer = Files.newBufferedWriter(Paths.get(path2));
			BufferedWriter writer2 = Files.newBufferedWriter(Paths.get(path3).toAbsolutePath());
			BufferedReader reader2 = Files.newBufferedReader(Paths.get(path4))) {
			
			/**************************************START GRAB RECEIVER'S PUBLIC KEY*****************************************************/
			byte[] receiverPublicKey = DatatypeConverter.parseHexBinary(reader2.readLine());
			X509EncodedKeySpec receiverPublicKey2 = new X509EncodedKeySpec(receiverPublicKey);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey receiverPublicKey3 = keyFactory.generatePublic(receiverPublicKey2);
			/***************************************END GRAB RECEIVER'S PUBLIC KEY******************************************************/
			
			

			/***********************************************START AES*********************************************************/
			KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
			aesKeyGen.init(128);
			SecretKey aesKey = aesKeyGen.generateKey();
			byte[] aesKey2 = aesKey.getEncoded();
			
			/*Encrypt Message*/
			byte[] plainText = reader.readLine().getBytes();
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, aesKey);
			byte[] cipherText = cipher.doFinal(plainText);
			
			/*Write cypherText and AES key in message*/
			writer.write(DatatypeConverter.printHexBinary(cipherText));
			writer.newLine();
			
			//Encrypt AES Key with Receiver's Public Key
			Cipher encryptsAesKey = Cipher.getInstance("RSA");
			encryptsAesKey.init(Cipher.ENCRYPT_MODE, receiverPublicKey3);
			byte[] encryptedAesKey = encryptsAesKey.doFinal(aesKey2);
			writer.write(DatatypeConverter.printHexBinary(encryptedAesKey));
			writer.newLine();
			/*****************************************************END AES*******************************************************/	
			
			

			/**************************************************START MAC********************************************************/			
		    Mac mac = Mac.getInstance("HmacSHA512");
		    mac.init(aesKey);
		    
		    /*Create MAC and append to file*/
		    byte[] macCode = mac.doFinal(cipherText);
		    writer.write(DatatypeConverter.printHexBinary(macCode));
		    /*************************************************END MAC***********************************************************/
			
		}catch(NoSuchAlgorithmException | IllegalArgumentException | NoSuchPaddingException | 
				InvalidKeyException | BadPaddingException | IOException | IllegalBlockSizeException | InvalidKeySpecException e){
			e.printStackTrace();
		}
	}
}
