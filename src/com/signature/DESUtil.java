package com.signature;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class DESUtil {
	
	/*
	 * �����Կ
	 */
	public static byte[] initKey() throws Exception{
		KeyGenerator keyGen = KeyGenerator.getInstance("DES");
		keyGen.init(56);
		SecretKey secretKey = keyGen.generateKey();
		return secretKey.getEncoded();
	}

	
	/*
	 * DES ����
	 */
	public static byte[] encrypt(byte[] data, byte[] key) throws Exception{
		SecretKey secretKey = new SecretKeySpec(key, "DES");
		
		Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		byte[] cipherBytes = cipher.doFinal(data);
		return cipherBytes;
	}
	
	
	/*
	 * DES ����
	 */
	public static byte[] decrypt(byte[] data, byte[] key) throws Exception{
		SecretKey secretKey = new SecretKeySpec(key, "DES");
		
		Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		byte[] plainBytes = cipher.doFinal(data);
		return plainBytes;
	}
	
	
	
	
	
	
	
	
	
}
