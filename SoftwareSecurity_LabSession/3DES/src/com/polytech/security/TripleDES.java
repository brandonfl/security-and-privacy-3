package com.polytech.security;



import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.util.*;

public class TripleDES{

	static public void main(String[] argv){
		
		Provider prov = new org.bouncycastle.jce.provider.BouncyCastleProvider();
		Security.addProvider(prov);
		
		try{
	
			if(argv.length>0){
			
				// Create a TripleDES object 
				TripleDES the3DES = new TripleDES();
			
				if(argv[0].compareTo("-ECB")==0){
					// ECB mode
				  	// encrypt ECB mode
				  	Vector Parameters= 
					  	the3DES.encryptECB(
					  			new FileInputStream(new File(argv[1])),  	// clear text file 
				   	  			new FileOutputStream(new File(argv[2])), 	// file encrypted
				   	  			"DES", 										// KeyGeneratorName
				   	  			"DES/ECB/NoPadding"); 						// CipherName 
				  	// decrypt ECB mode
				  	the3DES.decryptECB(Parameters,				 			// the 3 DES keys
				  				new FileInputStream(new File(argv[2])),  	// the encrypted file 
				   	  			new FileOutputStream(new File(argv[3])),	// the decrypted file
				   	  			"DES/ECB/NoPadding"); 		  				// CipherName
				}	
				else if(argv[0].compareTo("-CBC")==0){
					// decryption
				  	// encrypt CBC mode
				  	Vector Parameters = 
					  	the3DES.encryptCBC(
					  			new FileInputStream(new File(argv[1])),  	// clear text file 
				   	  			new FileOutputStream(new File(argv[2])), 	// file encrypted
				   	  			"DES", 										// KeyGeneratorName
					  			"DES/CBC/NoPadding"); 						// CipherName
				   	  			//"DES/CBC/PKCS5Padding"); 					// CipherName 
				  	// decrypt CBC mode	
				  	the3DES.decryptCBC(
				  				Parameters,				 					// the 3 DES keys
			  					new FileInputStream(new File(argv[2])),  	// the encrypted file 
			  					new FileOutputStream(new File(argv[3])),	// the decrypted file
				  				"DES/CBC/NoPadding"); 						// CipherName			
				  				//"DES/CBC/PKCS5Padding"); 		  			// CipherName	  
				}
			
			}
			
			else{
				System.out.println("java TripleDES -ECB clearTextFile EncryptedFile DecryptedFile");
				System.out.println("java TripleDES -CBC clearTextFile EncryptedFile DecryptedFile");
			} 
		}catch(Exception e){
			e.printStackTrace();
			System.out.println("java TripleDES -ECB clearTextFile EncryptedFile DecryptedFile");
			System.out.println("java TripleDES -CBC clearTextFile EncryptedFile DecryptedFile");
		}
	}

	
	/**
	 * 3DES ECB Encryption
	 */
	private Vector encryptECB(FileInputStream in, 
							FileOutputStream out, 
							String KeyGeneratorInstanceName, 
							String CipherInstanceName){
		try{
			
			KeyGenerator keyGen = KeyGenerator.getInstance(KeyGeneratorInstanceName);
			keyGen.init(new SecureRandom());
			SecretKey secretLevel1 = keyGen.generateKey();
			SecretKey secretLevel2 = keyGen.generateKey();
			SecretKey secretLevel3 = keyGen.generateKey();
			
			Cipher cipherLevel1 = Cipher.getInstance(CipherInstanceName);
			cipherLevel1.init(Cipher.ENCRYPT_MODE, secretLevel1);
			
			Cipher cipherLevel2 = Cipher.getInstance(CipherInstanceName);
			cipherLevel2.init(Cipher.DECRYPT_MODE, secretLevel2);
			
			Cipher cipherLevel3 = Cipher.getInstance(CipherInstanceName);
			cipherLevel3.init(Cipher.ENCRYPT_MODE, secretLevel3);
			
			StringBuilder stringBuilder = new StringBuilder();
			
			byte[] plainText  = in.readAllBytes();
			byte[] firstPass = cipherLevel1.doFinal(plainText);
			byte[] secondPass = cipherLevel2.doFinal(firstPass);
			byte[] thirdPass = cipherLevel3.doFinal(secondPass);
			
			out.write(thirdPass);
			out.close();
			
			Vector<SecretKey> vector = new Vector();
			vector.add(secretLevel1);
			vector.add(secretLevel2);
			vector.add(secretLevel3);
			
			return vector;
			
		}catch(Exception e){
			e.printStackTrace();
			return null;
		}
		
	}
	
	/**
	 * 3DES ECB Decryption 
	 */
	private void decryptECB(Vector Parameters, 
						FileInputStream in, 
						FileOutputStream out, 
						String CipherInstanceName){
		try{
			
			SecretKey secretLevel1 = (SecretKey) Parameters.get(0);
			SecretKey secretLevel2 = (SecretKey) Parameters.get(1);
			SecretKey secretLevel3 = (SecretKey) Parameters.get(2);
			
			Cipher cipherLevel1 = Cipher.getInstance(CipherInstanceName);
			cipherLevel1.init(Cipher.DECRYPT_MODE, secretLevel3);
			
			Cipher cipherLevel2 = Cipher.getInstance(CipherInstanceName);
			cipherLevel2.init(Cipher.ENCRYPT_MODE, secretLevel2);
			
			Cipher cipherLevel3 = Cipher.getInstance(CipherInstanceName);
			cipherLevel3.init(Cipher.DECRYPT_MODE, secretLevel1);
			
			byte[] plainText  = in.readAllBytes();
			byte[] firstPass = cipherLevel1.doFinal(plainText);
			byte[] secondPass = cipherLevel2.doFinal(firstPass);
			byte[] thirdPass = cipherLevel3.doFinal(secondPass);
			
			out.write(thirdPass);
			out.close();
			
		}catch(Exception e){
			e.printStackTrace();
		}

	}
	  
	/**
	 * 3DES CBC Encryption
	 */
	private Vector encryptCBC(FileInputStream in, 
							FileOutputStream out, 
							String KeyGeneratorInstanceName, 
							String CipherInstanceName){
		try{
			
			byte[] iv = new byte[128/8];
			new SecureRandom().nextBytes(iv);
			IvParameterSpec ivspec = new IvParameterSpec(iv);
			
			KeyGenerator keyGen = KeyGenerator.getInstance(KeyGeneratorInstanceName);
			keyGen.init(new SecureRandom());
			SecretKey secretLevel1 = keyGen.generateKey();
			SecretKey secretLevel2 = keyGen.generateKey();
			SecretKey secretLevel3 = keyGen.generateKey();
			
			IvParameterSpec IVLevel1 = new IvParameterSpec(new byte[8]);
			IvParameterSpec IVLevel2 = new IvParameterSpec(new byte[8]);
			IvParameterSpec IVLevel3 = new IvParameterSpec(new byte[8]);
			
			Cipher cipherLevel1 = Cipher.getInstance(CipherInstanceName);
			cipherLevel1.init(Cipher.ENCRYPT_MODE, secretLevel1, IVLevel1);
			
			Cipher cipherLevel2 = Cipher.getInstance(CipherInstanceName);
			cipherLevel2.init(Cipher.DECRYPT_MODE, secretLevel2, IVLevel2);
			
			Cipher cipherLevel3 = Cipher.getInstance(CipherInstanceName);
			cipherLevel3.init(Cipher.ENCRYPT_MODE, secretLevel3, IVLevel3);
			
			StringBuilder stringBuilder = new StringBuilder();
			
			byte[] plainText  = in.readAllBytes();
			byte[] firstPass = cipherLevel1.doFinal(plainText);
			byte[] secondPass = cipherLevel2.doFinal(firstPass);
			byte[] thirdPass = cipherLevel3.doFinal(secondPass);
			
			out.write(thirdPass);
			out.close();
			
			Vector vector = new Vector();
			vector.add(secretLevel1);
			vector.add(IVLevel1);
			vector.add(secretLevel2);
			vector.add(IVLevel2);
			vector.add(secretLevel3);
			vector.add(IVLevel3);
			
			return vector;
			
		}catch(Exception e){
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * 3DES CBC Decryption 
	 */
	private void decryptCBC(Vector Parameters, 
						FileInputStream in, 
						FileOutputStream out, 
						String CipherInstanceName){
		try{
		
			SecretKey secretLevel1 = (SecretKey) Parameters.get(0);
			IvParameterSpec IVLevel1 = (IvParameterSpec) Parameters.get(1);
			SecretKey secretLevel2 = (SecretKey) Parameters.get(2);
			IvParameterSpec IVLevel2 = (IvParameterSpec) Parameters.get(3);
			SecretKey secretLevel3 = (SecretKey) Parameters.get(4);
			IvParameterSpec IVLevel3 = (IvParameterSpec) Parameters.get(5);
			
			Cipher cipherLevel1 = Cipher.getInstance(CipherInstanceName);
			cipherLevel1.init(Cipher.DECRYPT_MODE, secretLevel3, IVLevel3);
			
			Cipher cipherLevel2 = Cipher.getInstance(CipherInstanceName);
			cipherLevel2.init(Cipher.ENCRYPT_MODE, secretLevel2, IVLevel2);
			
			Cipher cipherLevel3 = Cipher.getInstance(CipherInstanceName);
			cipherLevel3.init(Cipher.DECRYPT_MODE, secretLevel1, IVLevel1);
			
			byte[] plainText  = in.readAllBytes();
			byte[] firstPass = cipherLevel1.doFinal(plainText);
			byte[] secondPass = cipherLevel2.doFinal(firstPass);
			byte[] thirdPass = cipherLevel3.doFinal(secondPass);
			
			out.write(thirdPass);
			out.close();
			
		}catch(Exception e){
			e.printStackTrace();
		}

	}
	  

}