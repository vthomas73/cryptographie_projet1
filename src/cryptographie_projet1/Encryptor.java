package cryptographie_projet1;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Encryptor {
	private SecretKey key;
	private Cipher cipher;
	private String encryptionType;
	private String ALGO_OPTIONS = "/CBC/PKCS5PADDING";

	public SecretKey setRandomKey(String encryptionType) throws NoSuchAlgorithmException, NoSuchPaddingException {
		KeyGenerator keyGen = KeyGenerator.getInstance(encryptionType);
		this.encryptionType = encryptionType + this.ALGO_OPTIONS;
		keyGen.init(128);
		this.key = keyGen.generateKey();
		this.cipher = Cipher.getInstance(this.encryptionType);
		return this.key;
	}

	public SecretKey setKeyFromString(String key, String encryptionType)
			throws NoSuchAlgorithmException, NoSuchPaddingException {
		byte[] decodedKey = hexStringToByteArray(key);
		SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, encryptionType);
		this.key = originalKey;
		this.encryptionType = encryptionType + this.ALGO_OPTIONS;
		this.cipher = Cipher.getInstance(this.encryptionType);
		return this.key;
	}

	public byte[] encryption(byte[] msg, IvParameterSpec iv) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		if (iv != null) {
			this.cipher.init(Cipher.ENCRYPT_MODE, this.key, iv);
		} else {
			this.cipher.init(Cipher.ENCRYPT_MODE, this.key);
		}
		return cipher.doFinal(msg);
	}

	public byte[] decryption(byte[] msg, IvParameterSpec iv) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		if (iv != null) {
			this.cipher.init(Cipher.DECRYPT_MODE, this.key, iv);
		} else {
			this.cipher.init(Cipher.DECRYPT_MODE, this.key);
		}
		return cipher.doFinal(msg);

	}

	private static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	public byte[] get16BytesFromString(String msg) throws NoSuchAlgorithmException, UnsupportedEncodingException {
		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(msg.getBytes());
		return md.digest();
	}
	
	public byte[] calculateHMAC(byte[] data, String key)
		    throws NoSuchAlgorithmException, InvalidKeyException
		{
		    SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacSHA512");
		    Mac mac = Mac.getInstance("HmacSHA512");
		    mac.init(secretKeySpec);
		    return mac.doFinal(data);
		}
}
