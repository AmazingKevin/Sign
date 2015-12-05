package com.signature;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * @作者: 吴金龙
 * @时间:2015-12-5下午1:11:00
 * @包名:com.signature
 * @类名:DSASignatureUtil
 * @描述:TODO
 * 
 * @SVN版本号:$Rev$
 * @更新时间:$Date$
 * @更新人:$Author$
 * @更新描述:TODO
 */
public class DSASignatureUtil
{
	
	public static final String KEY_ALGORITHM="DSA";
	public static final String PUBLIC_KEY="DSA_PUBLIC_KEY";
	public static final String PRIVATE_KEY="DSA_PRIVATE_KEY";
	public static final String SIGNATURE_ALGORITHM="SHA1withDSA";
	public static final int KEY_SIZE=1024;
	/**
	 * 生成公私钥对
	 */
	public static Map<String,Object> initKey()
	{
		try
		{
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
			keyPairGenerator.initialize(KEY_SIZE);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			
			DSAPublicKey publicKey=(DSAPublicKey) keyPair.getPublic();
			DSAPrivateKey privateKey=(DSAPrivateKey) keyPair.getPrivate();
			
			Map<String,Object> keyMap=new HashMap<String,Object>();
			keyMap.put(PUBLIC_KEY, publicKey);
			keyMap.put(PRIVATE_KEY, privateKey);
			
			return keyMap;
			
		}
		catch (Exception e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		return null;
	}
	
	public static byte[] getPublicKey(Map<String,Object> keyMap)
	{
		DSAPublicKey publicKey= (DSAPublicKey) keyMap.get(PUBLIC_KEY);
		return publicKey.getEncoded();
	}
	
	public static byte[] getPrivateKey(Map<String,Object> keyMap)
	{
		DSAPrivateKey priKey= (DSAPrivateKey) keyMap.get(PRIVATE_KEY);
		return priKey.getEncoded();
	}
	
	/**
	 * 对原始数据 用私钥 进行签名
	 */
	public static byte[] sign(byte[] data,byte[] privateKey)
	{
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
		try
		{
			KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
			PrivateKey priKey = keyFactory.generatePrivate(keySpec);
			
			Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
			signature.initSign(priKey);
			signature.update(data);
			return signature.sign();
			
		}
		catch (  Exception e)
		{
			e.printStackTrace();
		}
		
		
		return null;
	}
	
	
	

	/**
	 * 根据原始数据,公钥,私钥,进行签名
	 */
	
	public static boolean verify(byte[] data,byte[] publicKey,byte[] sign)
	{
		X509EncodedKeySpec spec=new X509EncodedKeySpec(publicKey);
		try
		{
			KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
			PublicKey pubKey = keyFactory.generatePublic(spec);
			Signature signature=Signature.getInstance(SIGNATURE_ALGORITHM);
			signature.initVerify(pubKey);
			signature.update(data);
			return signature.verify(sign);
			
		}
		catch ( Exception e)
		{
			e.printStackTrace();
		}
		
		
		return false;
	}
}
