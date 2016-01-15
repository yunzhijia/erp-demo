package com.yunzhijia.open;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Encrypt utils class 
 * For more information please visit:  
 * 	http://open.kdweibo.com/wiki/doku.php?id=open:%E7%BB%84%E7%BB%87%E4%BA%BA%E5%91%98%E5%90%8C%E6%AD%A5
 * @author wenxiang_xu
 */
public class EncryptUtils {
	private static final String CIPHER_RSA = "RSA/ECB/PKCS1Padding";
	private static final String CIPHER_AES = "AES/ECB/PKCS5Padding";

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private static byte[] encryptLarger(byte[] data, Key key)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		javax.crypto.Cipher rsa = javax.crypto.Cipher.getInstance(CIPHER_RSA);
		rsa.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
		SecureRandom random = new SecureRandom();
		final byte[] secretKey = new byte[16];
		random.nextBytes(secretKey);
		final javax.crypto.Cipher aes = javax.crypto.Cipher
				.getInstance(CIPHER_AES);
		SecretKeySpec k = new SecretKeySpec(secretKey, "AES");
		aes.init(javax.crypto.Cipher.ENCRYPT_MODE, k);
		final byte[] ciphedKey = rsa.doFinal(secretKey);
		final byte[] ciphedData = aes.doFinal(data);
		byte[] result = new byte[128 + ciphedData.length];
		System.arraycopy(ciphedKey, 0, result, 0, 128);
		System.arraycopy(ciphedData, 0, result, 128, ciphedData.length);
		return result;
	}

	public static PrivateKey restorePrivateKey(byte[] bytes) throws Exception {
		PKCS8EncodedKeySpec pkcs = new PKCS8EncodedKeySpec(bytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(pkcs);
	}

	public static String encryptWithEncodeBase64UTF8(String orginalContent,
			Key key) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, UnsupportedEncodingException {
		return Base64.encodeBase64URLSafeString(encryptLarger(
				orginalContent.getBytes("UTF-8"), key));
	}

	public static byte[] getBytesFromFile(String filename) throws IOException {
		File f = new File(filename);
		if (!f.exists()) {
			throw new FileNotFoundException(filename);
		}

		ByteArrayOutputStream bos = new ByteArrayOutputStream((int) f.length());
		BufferedInputStream in = null;
		try {
			in = new BufferedInputStream(new FileInputStream(f));
			int buf_size = 1024;
			byte[] buffer = new byte[buf_size];
			int len = 0;
			while (-1 != (len = in.read(buffer, 0, buf_size))) {
				bos.write(buffer, 0, len);
			}
			return bos.toByteArray();
		} finally {
			try {
				in.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
			bos.close();
		}
	}
}
