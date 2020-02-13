package cryptographie_projet1;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Main {

	public static void main(String[] args) throws Exception {
		Utilities utilities = new Utilities();
		ProgramInformations programInfos = utilities.verifArgs(args);
		Encryptor encryptor = new Encryptor();
		// encryptor.setRandomKey("AES");

		/*
		 * Testing part
		 * 
		 * byte[] msg = { (byte)0x10, (byte)0x07, (byte)0x32, (byte) 0x19, (byte)0x22,
		 * (byte)0x15, (byte)0x33, (byte)0x30, (byte)0x21, (byte)0x01,
		 * (byte)0x11,(byte)0x37, (byte)0x11, (byte)0x28, (byte)0x00, (byte)0x27 };
		 */

		if (programInfos.filesInput.size() == 1) {
			encryptor.setKeyFromString(programInfos.key, "AES");
			byte[] msg = utilities.getBytesFromFile(programInfos.filesInput.get(0));
			//String test = utilities.convertBytesArrayToString(msg);
			//System.out.println(test);
			byte[] output = null ;
			if (programInfos.encryptionMode.equals("-enc")) {
				output = encryptor.encryption(msg);
			}
			else {
				output = encryptor.decryption(msg);
			}
			//test = utilities.convertBytesArrayToString(decrypted);
			//System.out.println(test);
			utilities.bytesToFile(output, programInfos.fileOutput);

		} else {
			Path tmp = Paths.get(programInfos.fileOutput);
			String locationFolder = tmp.getParent().toString();

			for (int i = 0; i < programInfos.filesInput.size(); i++) {
				File f = new File(programInfos.filesInput.get(i));
				String fileName = f.getName();
				
				programInfos.key = programInfos.key.substring(0,programInfos.key.length() - fileName.length());
				programInfos.key = programInfos.key + fileName;
				encryptor.setKeyFromString(programInfos.key, "AES");
				
				byte[] msg = utilities.getBytesFromFile(programInfos.filesInput.get(i));
			
				byte[] output = null ;
				if (programInfos.encryptionMode.equals("-enc")) {
					output = encryptor.encryption(msg);
				}
				else {
					output = encryptor.decryption(msg);
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
