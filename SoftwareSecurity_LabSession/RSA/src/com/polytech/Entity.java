package com.polytech;


import java.security.*;
import javax.crypto.*;

import java.io.*;

public class Entity{

	// keypair
	public PublicKey thePublicKey;
	private PrivateKey thePrivateKey;
	
	/**
	  * Entity Constructor
	  * Public / Private Key generation
	 **/
	public Entity(){
		try{
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(1024);
			KeyPair keyPair = keyPairGenerator.genKeyPair();

			this.thePublicKey = keyPair.getPublic();
			this.thePrivateKey = keyPair.getPrivate();
		}catch(Exception e){
			System.out.println("Signature error");
			e.printStackTrace();
		}
	}

	/**
	  * Sign a message
	  * Parameters
	  * aMessage : byte[] to be signed
	  * Result : signature in byte[] 
	  **/
	public byte[] sign(byte[] aMessage){
		
		try{
			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initSign(this.thePrivateKey);
			signature.update(aMessage);

			return signature.sign();
		}catch(Exception e){
			System.out.println("Signature error");
			e.printStackTrace();
			return null;
		}
		
	}
	
	/**
	  * Check aSignature is the signature of aMessage with aPK
	  * Parameters
	  * aMessage : byte[] to be signed
	  * aSignature : byte[] associated to the signature
	  * aPK : a public key used for the message signature
	  * Result : signature true or false
	  **/
	public boolean checkSignature(byte[] aMessage, byte[] aSignature, PublicKey aPK){
		try{
			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initVerify(aPK);
			signature.update(aMessage);

			return signature.verify(aSignature);
		}catch(Exception e){
			System.out.println("Verify signature error");
			e.printStackTrace();
			return false;
		}
	}
	
	
	/**
	  * Sign a message
	  * Parameters
	  * aMessage : byte[] to be signed
	  * Result : signature in byte[] 
	  **/
	public byte[] mySign(byte[] aMessage){
		
		try{
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, this.thePrivateKey);

			MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
			messageDigest.update(aMessage);
			byte[] digest = messageDigest.digest(aMessage);

			return cipher.doFinal(digest);
		}catch(Exception e){
			System.out.println("Signature error");
			e.printStackTrace();
			return null;
		}
		
	}
	
	/**
	  * Check aSignature is the signature of aMessage with aPK
	  * Parameters
	  * aMessage : byte[] to be signed
	  * aSignature : byte[] associated to the signature
	  * aPK : a public key used for the message signature
	  * Result : signature true or false
	  **/
	public boolean myCheckSignature(byte[] aMessage, byte[] aSignature, PublicKey aPK){
		try{
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, aPK);

			byte[] digest1 = cipher.doFinal(aSignature);
			MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
			messageDigest.update(aMessage);

			return digest1.equals(messageDigest.digest());
		}catch(Exception e){
			System.out.println("Verify signature error");
			e.printStackTrace();
			return false;
		}
	}	
	
	
	/**
	  * Encrypt aMessage with aPK
	  * Parameters
	  * aMessage : byte[] to be encrypted
	  * aPK : a public key used for the message encryption
	  * Result : byte[] ciphered message
	  **/
	public byte[] encrypt(byte[] aMessage, PublicKey aPK){
		try{
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, aPK);

			return cipher.doFinal(aMessage);
		}catch(Exception e){
			System.out.println("Encryption error");
			e.printStackTrace();
			return null;
		}
	}

	/**
	  * Decrypt aMessage with the entity private key
	  * Parameters
	  * aMessage : byte[] to be encrypted
	  * Result : byte[] deciphered message
	  **/
	public byte[] decrypt(byte[] aMessage){
		try{
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, this.thePrivateKey);

			return cipher.doFinal(aMessage);
		}catch(Exception e){
			System.out.println("Encryption error");
			e.printStackTrace();
			return null;
		}

	}


}