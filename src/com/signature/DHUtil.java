package com.signature;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

public class DHUtil {
	
	public static final String PUBLIC_KEY = "DHPublicKey";
	public static final String PRIVATE_KEY = "DHPrivateKey";

	/*
	 * �׷���ʼ����������Կ��
	 */
	public static Map<String, Object> initKey() throws Exception {
		// ʵ����Կ�������
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
		// ��ʼ����Կ�������    Ĭ����1024  512-1024 & 64�ı���
		keyPairGenerator.initialize(1024);
		// �����Կ��
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		// �õ��׷���Կ
		DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();
		// �õ��׷�˽Կ
		DHPrivateKey privateKey = (DHPrivateKey) keyPair.getPrivate();
		// ����Կ��˽Կ��װ��Map�У� ����֮��ʹ��
		Map<String, Object> keyMap = new HashMap<String, Object>();
		keyMap.put(PUBLIC_KEY, publicKey);
		keyMap.put(PRIVATE_KEY, privateKey);
		return keyMap;
	}

	/*
	 * �ҷ���ݼ׷���Կ��ʼ����������Կ��
	 */
	public static Map<String, Object> initKey(byte[] key) throws Exception {
		// ���׷���Կ���ֽ�����ת��ΪPublicKey
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
		// ʵ����Կ����
		KeyFactory keyFactory = KeyFactory.getInstance("DH");
		// ����׷���ԿpubKey
		DHPublicKey dhPublicKey = (DHPublicKey) keyFactory.generatePublic(keySpec);
		// �����׷���Կ���õ������
		DHParameterSpec dhParameterSpec = dhPublicKey.getParams();
		// ʵ����Կ�������
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
		// �ü׷���Կ��ʼ����Կ�������
		keyPairGenerator.initialize(dhParameterSpec);
		// ������Կ��
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		// �õ��ҷ���Կ
		DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();
		// �õ��ҷ�˽Կ
		DHPrivateKey privateKey = (DHPrivateKey) keyPair.getPrivate();
		// ����Կ��˽Կ��װ��Map�У� ����֮��ʹ��
		Map<String, Object> keyMap = new HashMap<String, Object>();
		keyMap.put(PUBLIC_KEY, publicKey);
		keyMap.put(PRIVATE_KEY, privateKey);
		return keyMap;
	}

	/*
	 * ��ݶԷ��Ĺ�Կ���Լ���˽Կ��� ������Կ
	 */
	public static byte[] getSecretKey(byte[] publicKey, byte[] privateKey) throws Exception {
		// ʵ����Կ����
		KeyFactory keyFactory = KeyFactory.getInstance("DH");
		// ����Կ���ֽ�����ת��ΪPublicKey
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKey);
		PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
		// ��˽Կ���ֽ�����ת��ΪPrivateKey
		PKCS8EncodedKeySpec priKeySpec = new PKCS8EncodedKeySpec(privateKey);
		PrivateKey priKey = keyFactory.generatePrivate(priKeySpec);
		
		// ׼��������Ϲ�Կ��˽Կ��ɱ�����ԿSecretKey
		// ��ʵ��KeyAgreement
		KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
		// ���Լ���˽Կ��ʼ��keyAgreement
		keyAgreement.init(priKey);
		// ��϶Է��Ĺ�Կ��������
		keyAgreement.doPhase(pubKey, true);
		// ��ʼ��ɱ�����ԿSecretKey ��Կ�㷨Ϊ�Գ������㷨
		SecretKey secretKey = keyAgreement.generateSecret("DES"); //DES 3DES AES
		return secretKey.getEncoded();
	}
	
	/*
	 * �� Map ��ȡ�ù�Կ
	 */
	public static byte[] getPublicKey(Map<String, Object> keyMap){
		DHPublicKey key = (DHPublicKey) keyMap.get(PUBLIC_KEY);
		return key.getEncoded();
	}
	
	/*
	 * �� Map ��ȡ��˽Կ
	 */
	public static byte[] getPrivateKey(Map<String, Object> keyMap){
		DHPrivateKey key = (DHPrivateKey) keyMap.get(PRIVATE_KEY);
		return key.getEncoded();
	}
	
	
	
	
	
	
	
	
	
	
	
	
}
