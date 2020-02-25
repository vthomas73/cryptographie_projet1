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
	private String ALGO_OPTIONS_ECB = "/ECB/NoPadding";

	public SecretKey setRandomKey(String encryptionType) throws NoSuchAlgorithmException, NoSuchPaddingException {
		KeyGenerator keyGen = KeyGenerator.getInstance(encryptionType);
		this.encryptionType = encryptionType + this.ALGO_OPTIONS_ECB;
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
		this.encryptionType = encryptionType + this.ALGO_OPTIONS_ECB;
		this.cipher = Cipher.getInstance(this.encryptionType);
		return this.key;
	}

	// Function that is creating the ciphertext using a homemade CBC algorithm
	public byte[] cipherCbc(String mode, byte[] msg, IvParameterSpec iv) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		// Initialize an empty byte array
		byte[] blocXor = null;
		
		// Get the number of bloc of 16 bytes that are completely filled with the message
		int numberOfBloc = getNumberFullBloc(msg);
		
		//Counter for the numberOfBloc
		int cptNbBloc = 0;
		
		// Initialize an empty byte array
		byte[] cipherXor = null;
		
		// Initialize an empty byte array
		byte[] cipherDecrypt = null;
		
		// Create a message with the final length (the one which will be a multiple of 16 bytes) 
			byte[] final_msg =null;
			final_msg = messagePadding(msg);
		
		// Initialize an empty byte array
		byte[][] msg16Bloc = new byte[numberOfBloc][16];
		
		//copy the message into an array with a length multiple of 16 bytes
		msg = messagePadding(msg);
		
		// Initialise a 2D array, each line represent a 16 bytes bloc of data from the message
		int i = 0;
		while(i < (numberOfBloc)) {
			for(int j = 0; j < 16; j++) {
				msg16Bloc[i][j] += msg[i*16+j];
			}
			i++;
		}

		while(cptNbBloc < numberOfBloc) {
			// To see if we are in Encrypt or Decrypt mode
			if(mode == "Encrypt") {
				// Initialize the cipher with a key and in Encrypt mode
				this.cipher.init(Cipher.ENCRYPT_MODE, this.key);
				// If the initialization vector exist
				if(iv != null) {
					if(cptNbBloc == 0) {
						// We start with a XOR between the IV and the first 16 bytes
						blocXor = xor(iv.getIV(), msg16Bloc[cptNbBloc]);
						// Encryption of the previous XOR result
						cipherXor = cipher.doFinal(blocXor);
						// Add the encrypted XOR to our final message
						add16ByteBlocToArray(0,final_msg,cipherXor);
						cptNbBloc++;
					}
					if(cptNbBloc < numberOfBloc) {
						// Making a XOR between the previous encrypted XOR and the next 16 bytes of the message
						blocXor = xor(cipherXor,msg16Bloc[cptNbBloc]);
						// Encryption of the previous XOR result
						cipherXor = cipher.doFinal(blocXor);
						// Add the encrypted XOR to our final message
						add16ByteBlocToArray(cptNbBloc,final_msg,cipherXor);
					}
					
					
				} else {
					
				}
				
			} else if (mode == "Decrypt") {
				this.cipher.init(Cipher.DECRYPT_MODE, this.key);
				// If the initialization vector exist
				if(iv != null) {
					if(cptNbBloc == 0) {
						// We start with a decryption of the first bloc of the ciphertext
						cipherDecrypt = cipher.doFinal(msg16Bloc[cptNbBloc]);
						// Then we do a XOR between the IV and the first 16 bytes of ciphertext that we just have decrypt
						blocXor = xor(iv.getIV(),cipherDecrypt);
						// Add the decrypted XOR to our final message
						add16ByteBlocToArray(cptNbBloc,final_msg,blocXor);
						cptNbBloc++;
					}
					if(cptNbBloc < numberOfBloc) {
						// Decryption of the next bloc of the ciphertext
						cipherDecrypt = cipher.doFinal(msg16Bloc[cptNbBloc]);
						// Making a XOR between the previous decrypted ciphertext and the next 16 bytes of ciphertext that we just have decrypt
						blocXor = xor(msg16Bloc[cptNbBloc-1],cipherDecrypt);
						// Add the encrypted XOR to our final message
						add16ByteBlocToArray(cptNbBloc,final_msg,blocXor);
					}
				} else {
				}
			}
			cptNbBloc++;
		}
		//return the ciphertext
		return final_msg;
	}
	
	// Function that add a table to another the goal is to create our final message here
	private byte[] add16ByteBlocToArray(int index, byte[] new_tab, byte[] tab_to_add) {
		int j = index*16;
		
		// copy the tab_to_add into the new_tab
		for(int i = 0; i < tab_to_add.length; i++) {
			new_tab[j] = tab_to_add[i];
			j++;
		}
		return new_tab;
	}
	
	// Function that give the number of bloc of 16 bytes that is completely fill with the message
	private int getNumberFullBloc(byte[] msg) {
		int k = 0;
		
		// If the length of the message is not a multiple of 16 byte
		if((msg.length % 16) != 0) {
			// Create a counter that will stop once he will find the right K that verify k*16 > length of the message
			while (k*16 < msg.length) {
				k++;
			}
		} else {
			// If the message length is already a multiple of 16 bytes, we just divide it by 16 to get the number of full bloc of 16 bytes
			k = msg.length / 16;
		}
		return k;
	}
	
	// Function that is creating a Padding on a message if the length of this one is not a multiple of 16 byte
	private byte[] messagePadding(byte[] msg) {
		// Initialize an empty byte array
		byte[] new_message = null;
		int numberOfBloc = getNumberFullBloc(msg);
		
		// Initialize a padding value with the amount of bytes we have to add to the original message in order to get a total length multiple of 16 bytes
		Integer padding =  (Integer) ((numberOfBloc*16) - msg.length);
		// Initialize the byte array with the right length
		new_message = new byte[msg.length + padding];
		int j = 0;
		// Copy the initial message into the larger byte array
		for (byte b : msg) {
			new_message[j] = b;
			j++;
		}
		
		// Fill the empty case of the byte array with the padding number
		for(int i =0; i < padding; i++) {
			new_message[msg.length + i] = padding.byteValue();
		}
		
		// Return the new message with the right length
		return new_message;
	}
	
	// Function that allow to do a XOR between two bloc of bytes
	private byte[] xor(byte[] bloc1, byte[] bloc2) {
		int i = 0;
		// Initialize the maxLength either on bloc1 or bloc2 depending which one has the biggest length
		int maxLength = (bloc1.length >= bloc2.length) ? bloc1.length : bloc2.length;
		
		// Initialize a byte array with the maxLength
		byte[] blocXor = new byte[maxLength];
		
		// Do a XOR between the two blocs of bytes
		if(bloc1.length >= bloc2.length) {
			for (byte b : bloc2)
				blocXor[i] = (byte) (b ^ bloc1[i++]);
		} else {
			for (byte b : bloc1)
				blocXor[i] = (byte) (b ^ bloc2[i++]);
		}
		// return the Byte array with the the result of the XOR in it
		return blocXor;
	}
	
	public byte[] removeBytesAdded(byte[] msg) {
		// Creation of a byte array that will get the new_message
		byte[] new_message = msg;
		// Get the last byte in the message
		int lastBit = msg[msg.length -1];
		// Set a Boolean as true if he turn to false then the message will not be modify
		boolean verif = true;
		
		// To see if the last byte represent a PCKS5Padding byte or not
		for(int i = 1; i <= lastBit; i++) {
			if(msg.length-i >= 0) {
				if(msg[msg.length-i] != lastBit) {
					verif = false;
				}
			}
		}
		
		// if the last byte represent a PCKS5Padding byte
		if(verif) {
			// put the message int new_message without the padding
			new_message = new byte[msg.length - lastBit];
			for(int j = 0; j < new_message.length; j++){
				new_message[j] = msg[j];
			}
		}
		
			
		return new_message;
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
