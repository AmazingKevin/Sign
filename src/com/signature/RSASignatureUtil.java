package com.signature;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * @作者: 吴金龙
 * @时间:2015-12-5上午11:54:04
 * @包名:com.signature
 * @类名:RSASignatureUtil
 * @描述:TODO
 * 
 * @SVN版本号:$Rev$
 * @更新时间:$Date$
 * @更新人:$Author$
 * @更新描述:TODO
 */
public class RSASignatureUtil
{
	public static final String KEY_ALGORITHM="RSA";
	public static final String RSA_PUBLIC_KEY="RSA_PUBLIC_KEY";
	public static final String RSA_PRIVATE_KEY="RSA_PRIVATE_KEY";
	public static final String SIGNATURE_ALGORITHM="MD5withRSA";
	
	/**
	 * 生成公私钥对
	 */
	public static Map<String,Object> initKey()
	{
		try
		{
			KeyPairGenerator keypairgenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
			
			KeyPair keyPair = keypairgenerator.generateKeyPair();
			
			RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
			RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
			
			Map<String,Object> map=new HashMap<String,Object>();
			
			map.put(RSA_PUBLIC_KEY, publicKey);
			map.put(RSA_PRIVATE_KEY, privateKey);
			
			return map;
		}
		catch (NoSuchAlgorithmException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		return null;
	}
	
	
	public static byte[] getPublicKey(Map<String,Object>  map)
	{
		RSAPublicKey publicKey=	(RSAPublicKey) map.get(RSA_PUBLIC_KEY);
		return publicKey.getEncoded();
	}
	
	
	public static byte[] getPrivateKey(Map<String,Object>  map)
	{
		RSAPrivateKey privateKey=(RSAPrivateKey) map.get(RSA_PRIVATE_KEY);
		return privateKey.getEncoded();
	}
	
	
	
	/**
	 * 对原始数据进行私钥签名
	 */
	
	public static byte[] sign(byte[] data,byte[] privateKey)
	{
		
		
		try
		{
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey);
			KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
			PrivateKey priKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
			
			Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
			signature.initSign(priKey);
			signature.update(data);
			
			return signature.sign();
		}
		catch (NoSuchAlgorithmException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		catch (InvalidKeySpecException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		catch (InvalidKeyException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		catch (SignatureException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		
		return null;
	}
	
	/**
	 * 根据原始数据,公钥,签名值进行验证
	 */
	public static  boolean verify(byte[] data,byte[] publicKey,byte[] sign)
	{
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
		
		try
		{
			KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
			PublicKey pubKey = keyFactory.generatePublic(keySpec);
			Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
			signature.initVerify(pubKey);
			signature.update(data);
			return signature.verify(sign);
			
		}
		catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		}
		catch (InvalidKeySpecException e)
		{
			e.printStackTrace();
		}
		catch (SignatureException e)
		{
			e.printStackTrace();
		}
		catch (InvalidKeyException e)
		{
			e.printStackTrace();
		}
		
		
		
		return false;
	}
}
