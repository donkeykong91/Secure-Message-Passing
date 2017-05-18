package main;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class Receiver {
	
	public void init() {
		
		String path = "cypheredMessage.txt", path2 = "decypheredMessage.txt", path3 = "receiverPubAndPrivKeys.txt";
		
		try(BufferedReader reader = Files.newBufferedReader(Paths.get(path));
			BufferedWriter writer = Files.newBufferedWriter(Paths.get(path2));
			BufferedReader reader2 = Files.newBufferedReader(Paths.get(path3).toAbsolutePath())) {
			
			/**************************************START GRAB PRIVATE KEY*****************************************************/
			reader2.readLine();
			byte[] privateKey = DatatypeConverter.parseHexBinary(reader2.readLine());
			PKCS8EncodedKeySpec privateKey2 = new PKCS8EncodedKeySpec(privateKey);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateKey3 = keyFactory.generatePrivate(privateKey2);
			/***************************************END GRAB PRIVATE KEY******************************************************/
			
			
			
			/****************************************START GRAB CYPHERTEXT****************************************************/
			byte[] cipherText = DatatypeConverter.parseHexBinary(reader.readLine());
			byte[] encryptedAesKey = DatatypeConverter.parseHexBinary(reader.readLine());
			byte[] mac = DatatypeConverter.parseHexBinary(reader.readLine());
			
			/********************************************END GRAB CYPHERTEXT**************************************************/

			
			
			/*******************************************START DECRYPT AES KEY*************************************************/
			Cipher decryptsAesKey = Cipher.getInstance("RSA");
			decryptsAesKey.init(Cipher.DECRYPT_MODE, privateKey3);
			byte[] decryptedAesKey = decryptsAesKey.doFinal(encryptedAesKey);
			
			/********************************************END DECRYPT AES KEY**************************************************/
			
			
			
			/*******************************************START MAC CHECK*******************************************************/
			Mac mac2 = Mac.getInstance("HmacSHA512");
			SecretKey decryptedAesKey2 = new SecretKeySpec(decryptedAesKey, 0, decryptedAesKey.length, "AES");
			mac2.init(decryptedAesKey2);
			mac2.update(cipherText);
			byte[] calculatedMacCode = mac2.doFinal();
			boolean macsAgree = true;
			
		    if (calculatedMacCode.length != calculatedMacCode.length) {
		        macsAgree = false;
		        System.out.println("Sender MAC and calculated MAC lengths are not the same.");
		        
		    }else{
		        for (int i = 0; i < mac.length; i++) {
		            if (mac[i] != calculatedMacCode[i]) {
		               macsAgree = false;
		               System.out.println("Sender MAC and calculated MAC are different. Message cannot be authenticated.");
		               break;
		            }
		        }
		    }
	        
	        if(macsAgree)
	        {
	        	System.out.println("Message authenticated successfully.");
	        }
			/*******************************************END MAC CHECK*********************************************************/
	        


	        /*******************************************START MESSAGE DECRYPTION**********************************************/
	        /*Decrypt Message*/
	        Cipher decipher = Cipher.getInstance("AES");
	        decipher.init(Cipher.DECRYPT_MODE, decryptedAesKey2);
	        byte[] decipheredText = decipher.doFinal(cipherText);
	        
	        /*Write decipheredText in message*/
	        writer.write(new String(decipheredText));
	        /********************************************END MESSAGE DECRYPTION***********************************************/
				
			}catch(NoSuchAlgorithmException | IllegalArgumentException | NoSuchPaddingException | 
					InvalidKeyException | BadPaddingException | IOException | IllegalBlockSizeException | InvalidKeySpecException e){
				e.printStackTrace();
			}	
	}
}
