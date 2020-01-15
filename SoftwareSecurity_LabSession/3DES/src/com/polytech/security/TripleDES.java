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
		
			// GENERATE 3 DES KEYS
		
			// CREATE A DES CIPHER OBJECT 
				// WITH CipherInstanceName
				// FOR ENCRYPTION 
				// WITH THE FIRST GENERATED DES KEY
			
			// CREATE A DES CIPHER OBJECT 
				// WITH CipherInstanceName
				// FOR DECRYPTION
				// WITH THE SECOND GENERATED DES KEY
				
			// CREATE A DES CIPHER OBJECT 
				// WITH CipherInstanceName 
				// FOR ENCRYPTION
				// WITH THE THIRD GENERATED DES KEY
				
			// GET THE MESSAGE TO BE ENCRYPTED FROM IN 
			
			// CIPHERING     
				// CIPHER WITH THE FIRST KEY
				// DECIPHER WITH THE SECOND KEY
				// CIPHER WITH THE THIRD KEY
				// write encrypted file

			// WRITE THE ENCRYPTED DATA IN OUT
			
			// return the DES keys list generated		
			return null;
			
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

			// CREATE A DES CIPHER OBJECT 
				// WITH CipherInstanceName
				// FOR DECRYPTION 
				// WITH THE THIRD GENERATED DES KEY
			
			// CREATE A DES CIPHER OBJECT 
				// WITH CipherInstanceName
				// FOR ENCRYPTION
				// WITH THE SECOND GENERATED DES KEY
				
			// CREATE A DES CIPHER OBJECT FOR ENCRYPTION
				// WITH CipherInstanceName
				// FOR DECRYPTION
				// WITH THE FIRST GENERATED DES KEY
			
			// GET THE ENCRYPTED DATA FROM IN
			
			// DECIPHERING     
				// DECIPHER WITH THE THIRD KEY
				// 	CIPHER WITH THE SECOND KEY
				// 	DECIPHER WITH THE FIRST KEY

			// WRITE THE DECRYPTED DATA IN OUT
			
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
		
			// GENERATE 3 DES KEYS
			// GENERATE THE IV
		
			// CREATE A DES CIPHER OBJECT 
				// WITH CipherInstanceName
				// FOR ENCRYPTION 
				// WITH THE FIRST GENERATED DES KEY
			
			// CREATE A DES CIPHER OBJECT 
				// WITH CipherInstanceName
				// FOR DECRYPTION
				// WITH THE SECOND GENERATED DES KEY
				
			// CREATE A DES CIPHER OBJECT 
				// WITH CipherInstanceName 
				// FOR ENCRYPTION
				// WITH THE THIRD GENERATED DES KEY
				
			// GET THE DATA TO BE ENCRYPTED FROM IN 
			
			// CIPHERING     
				// CIPHER WITH THE FIRST KEY
				// DECIPHER WITH THE SECOND KEY
				// CIPHER WITH THE THIRD KEY

			// WRITE THE ENCRYPTED DATA IN OUT
			
			// return the DES keys list generated		
			return null;
			
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
		
			// CREATE A DES CIPHER OBJECT 
				// WITH CipherInstanceName
				// FOR DECRYPTION  
				// WITH THE THIRD GENERATED DES KEY
			
			// CREATE A DES CIPHER OBJECT 
				// WITH CipherInstanceName
				// FOR ENCRYPTION 
				// WITH THE SECOND GENERATED DES KEY
				
			// CREATE A DES CIPHER OBJECT FOR ENCRYPTION
				// WITH CipherInstanceName
				// FOR DECRYPTION 
				// WITH THE FIRST GENERATED DES KEY
			
			// GET ENCRYPTED DATA FROM IN
			
			// DECIPHERING     
				// DECIPHER WITH THE THIRD KEY
				// 	CIPHER WITH THE SECOND KEY
				// 	DECIPHER WITH THE FIRST KEY

			// WRITE THE DECRYPTED DATA IN OUT
			
		}catch(Exception e){
			e.printStackTrace();
		}

	}
	  

}