package cryptographie_projet1;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

import javax.crypto.spec.IvParameterSpec;

public class Main {

	public static void main(String[] args) throws Exception {
		Utilities utilities = new Utilities();
		ProgramInformations programInfos = utilities.verifArgs(args);
		Encryptor encryptor = new Encryptor();
		// encryptor.setRandomKey("AES");

		
		  //Testing part
		  
		  /*byte[] msg = { (byte)0x10, (byte)0x07, (byte)0x32, (byte) 0x19, (byte)0x22,
		  (byte)0x15, (byte)0x33, (byte)0x30, (byte)0x21, (byte)0x01,
		  (byte)0x11,(byte)0x37, (byte)0x11, (byte)0x28, (byte)0x00, (byte)0x27 };*/
		 

		if (programInfos.filesInput.size() == 1) {
			// FileTime creationTime = (FileTime) Files.getAttribute(fInput.toPath(),
			// "creationTime");
			File fInput = new File(programInfos.filesInput.get(0));
			String fileNameInput = fInput.getName();
			File fOutput = new File(programInfos.fileOutput);
			String fileNameOutput = fOutput.getName();
			encryptor.setKeyFromString(programInfos.key, "AES");
			byte[] msg = utilities.getBytesFromFile(programInfos.filesInput.get(0));
			byte[] output = null;
			if (programInfos.encryptionMode.equals("-enc")) {
				//output = encryptor.encryption(msg, new IvParameterSpec(encryptor.get16BytesFromString(fileNameOutput)));
				//output = encryptor.encryption(msg, new IvParameterSpec(encryptor.get16BytesFromString("test.txt")));
				output = encryptor.cipherCbc("Encrypt",msg, new IvParameterSpec(encryptor.get16BytesFromString("test.txt")));
				byte[] hmac = encryptor.calculateHMAC(msg, "9^%bNhi8Q^CQ#@G1%^5KX1fXT9Gl&x");
				byte[] msgFinal = new byte[output.length + hmac.length];
				System.arraycopy(output, 0, msgFinal, 0, output.length);
				System.arraycopy(hmac, 0, msgFinal, output.length, hmac.length);
				output = msgFinal;
			} else {
				byte[] hmacGetted = Arrays.copyOfRange(msg, msg.length - 64, msg.length);
				msg = Arrays.copyOfRange(msg, 0, msg.length - 64);
				//output = encryptor.decryption(msg, new IvParameterSpec(encryptor.get16BytesFromString(fileNameInput)));
				//output = encryptor.decryption(msg, new IvParameterSpec(encryptor.get16BytesFromString("test.txt")));
				output = encryptor.cipherCbc("Decrypt",msg, new IvParameterSpec(encryptor.get16BytesFromString("test.txt")));
				output = encryptor.removeBytesAdded(output);
				byte[] hmac = encryptor.calculateHMAC(output, "9^%bNhi8Q^CQ#@G1%^5KX1fXT9Gl&x");
				if (Arrays.equals(hmac, hmacGetted))
				    System.out.println("Intégrité vérifiée, le fichier n'a pas été altéré");
			}
			utilities.bytesToFile(output, programInfos.fileOutput);

		} else {
			Path tmp = Paths.get(programInfos.fileOutput);
			String locationFolder = tmp.getParent().toString();

			for (int i = 0; i < programInfos.filesInput.size(); i++) {
				// FileTime creationTime = (FileTime) Files.getAttribute(fInput.toPath(),
				// "creationTime");
				File fInput = new File(programInfos.filesInput.get(i));
				String fileName = fInput.getName();

				encryptor.setKeyFromString(programInfos.key, "AES");

				byte[] msg = utilities.getBytesFromFile(programInfos.filesInput.get(i));

				byte[] output = null;
				if (programInfos.encryptionMode.equals("-enc")) {
					
					//output = encryptor.encryption(msg, new IvParameterSpec(encryptor.get16BytesFromString(fileName)));
					//output = encryptor.encryption(msg, new IvParameterSpec(encryptor.get16BytesFromString("test.txt")));
					output = encryptor.cipherCbc("Encrypt",msg, new IvParameterSpec(encryptor.get16BytesFromString("test.txt")));
					byte[] hmac = encryptor.calculateHMAC(msg, "9^%bNhi8Q^CQ#@G1%^5KX1fXT9Gl&x");
					byte[] msgFinal = new byte[output.length + hmac.length];
					System.arraycopy(output, 0, msgFinal, 0, output.length);
					System.arraycopy(hmac, 0, msgFinal, output.length, hmac.length);
					output = msgFinal;
				} else {
					byte[] hmacGetted = Arrays.copyOfRange(msg, msg.length - 64, msg.length);
					msg = Arrays.copyOfRange(msg, 0, msg.length - 64);
					//output = encryptor.decryption(msg, new IvParameterSpec(encryptor.get16BytesFromString(fileName)));
					//output = encryptor.decryption(msg, new IvParameterSpec(encryptor.get16BytesFromString("test.txt")));
					output = encryptor.cipherCbc("Decrypt",msg, new IvParameterSpec(encryptor.get16BytesFromString("test.txt")));
					output = encryptor.removeBytesAdded(output);
					byte[] hmac = encryptor.calculateHMAC(output, "9^%bNhi8Q^CQ#@G1%^5KX1fXT9Gl&x");
					if (Arrays.equals(hmac, hmacGetted))
					    System.out.println("Intégrité vérifiée pour le fichier " + fileName + ", le fichier n'a pas été altéré");
				}
				utilities.bytesToFile(output, locationFolder + "/" + fileName);
			}
			Utilities.pack(locationFolder, programInfos.fileOutput + ".zip");
			for (int i = 0; i < programInfos.filesInput.size(); i++) {
				File f = new File(programInfos.filesInput.get(i));
				String fileName = f.getName();
				f = new File(locationFolder + "/" + fileName);
				f.delete();
			}

		}
	}
}
