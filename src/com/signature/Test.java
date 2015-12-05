package com.signature;

import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.Map;

/**
 * @作者: 吴金龙
 * @时间:2015-12-5上午11:43:07
 * @包名:com.signature
 * @类名:Test
 * @描述:TODO
 * 
 * @SVN版本号:$Rev$
 * @更新时间:$Date$
 * @更新人:$Author$
 * @更新描述:TODO
 */
public class Test
{

	public static final String	DATA	= "wolegex";

	public static void main(String[] args)
	{
		demo2();
	}

	public void demo1()
	{
		Map<String, Object> keyMap = RSASignatureUtil.initKey();

		byte[] publicKey = RSASignatureUtil.getPublicKey(keyMap);
		byte[] privateKey = RSASignatureUtil.getPrivateKey(keyMap);

		System.out.println("publicKey:" + BytesToHex.fromBytesToHex(publicKey));
		System.out.println("privateKey:" + BytesToHex.fromBytesToHex(privateKey));

		byte[] sign = RSASignatureUtil.sign(DATA.getBytes(), privateKey);
		System.out.println("RSA Sign" + BytesToHex.fromBytesToHex(sign));

		boolean verify = RSASignatureUtil.verify(DATA.getBytes(), publicKey, sign);

		System.out.println("verify:" + verify);
	}

	public static void demo2()
	{
		Map<String, Object> keyMap = DSASignatureUtil.initKey();
		byte[] publicKey = DSASignatureUtil.getPublicKey(keyMap);
		byte[] privateKey = DSASignatureUtil.getPrivateKey(keyMap);
		
		System.out.println("publicKey:"+BytesToHex.fromBytesToHex(publicKey));
		System.out.println("privateKey:"+BytesToHex.fromBytesToHex(privateKey));
		byte[] sign = DSASignatureUtil.sign(DATA.getBytes(), privateKey);		
		System.out.println("sign:"+BytesToHex.fromBytesToHex(sign));

		
		boolean verify = DSASignatureUtil.verify(DATA.getBytes(), publicKey, sign);
		
		System.out.println("verify:::"+verify);
	}

}
