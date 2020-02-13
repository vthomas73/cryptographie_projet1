package cryptographie_projet1;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class Encryptor {
	private SecretKey key; 
	private String encryptionType ;
	
	public SecretKey setRandomKey(String encryptionType) throws NoSuchAlgorithmException {
		this.encryptionType = encryptionType;
		KeyGenerator keyGen = KeyGenerator.getInstance(this.encryptionType);
		keyGen.init(256); 
		return keyGen.generateKey();
	}
	
	public void setKey(SecretKey key) {
		this.key = key;
	}
	
	public byte[] encryption(byte[] msg) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		 Cipher cipher = Cipher.getInstance(this.encryptionType);
	     cipher.init(Cipher.ENCRYPT_MODE, this.key);
	     byte[] encryptedMsg = cipher.doFinal(msg);
	     return encryptedMsg;
	}
	
	public byte[] decryption(byte[] msg) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		 Cipher cipher = Cipher.getInstance(this.encryptionType);
	     cipher.init(Cipher.DECRYPT_MODE, this.key);
	     byte[] encryptedMsg = cipher.doFinal(msg);
	     return encryptedMsg;
	}

}
