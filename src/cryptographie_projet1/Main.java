package cryptographie_projet1;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.spec.IvParameterSpec;

public class Main {

	public static void main(ProgramInformations programInfos) throws Exception {
		Utilities utilities = new Utilities();
		// ProgramInformations programInfos = utilities.verifArgs(args);
		System.out.println(programInfos.toString());
		Encryptor encryptor = new Encryptor();
		SecureRandom random = new SecureRandom();
		byte[] iv = new byte[16];
		// encryptor.setRandomKey("AES");

		// Testing part

		/*
		 * byte[] msg = { (byte)0x10, (byte)0x07, (byte)0x32, (byte) 0x19, (byte)0x22,
		 * (byte)0x15, (byte)0x33, (byte)0x30, (byte)0x21, (byte)0x01,
		 * (byte)0x11,(byte)0x37, (byte)0x11, (byte)0x28, (byte)0x00, (byte)0x27 };
		 */

		/*
		 * byte[] msg = { (byte)0x10, (byte)0x07, (byte)0x32, (byte) 0x19, (byte)0x22,
		 * (byte)0x15, (byte)0x33, (byte)0x30, (byte)0x21, (byte)0x01,
		 * (byte)0x11,(byte)0x37, (byte)0x11, (byte)0x28, (byte)0x00, (byte)0x27 };
		 */

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

				// Question 1
				// Generate a secure random IV
				iv = random.generateSeed(16);
				FileWriter writer = null;
				if (programInfos.padding) {
					output = encryptor.cipherCbc("Encrypt", msg, new IvParameterSpec(iv));
				}
				// Question 6
				else {
					File cfg = new File(new File(programInfos.fileOutput).getAbsolutePath() + "crypto_cfg");
					writer = new FileWriter(cfg);
					writer.write(new String(new IvParameterSpec(iv).getIV()));
					output = encryptor.cipherCts("Encrypt", msg, new IvParameterSpec(iv));

				}
				if (programInfos.integrity) {
					byte[] hmac = encryptor.calculateHMAC(msg, "9^%bNhi8Q^CQ#@G1%^5KX1fXT9Gl&x");
					if (!programInfos.padding)
						writer.write(" " + new String(hmac));
					else {
						byte[] msgFinal = new byte[iv.length + output.length + hmac.length];
						System.arraycopy(iv, 0, msgFinal, 0, iv.length);
						System.arraycopy(output, 0, msgFinal, iv.length, output.length);
						System.arraycopy(hmac, 0, msgFinal, iv.length + output.length, hmac.length);
						output = msgFinal;
					}
				} else {
					byte[] msgFinal = new byte[iv.length + output.length];
					System.arraycopy(iv, 0, msgFinal, 0, iv.length);
					System.arraycopy(output, 0, msgFinal, iv.length, output.length);
					output = msgFinal;
				}
				if(!programInfos.padding) {
					writer.write("\n");
					writer.close();
				}
			} else {
				// Question 1 :
				byte[] hmacGetted = null;
				String[] splited = null;
				if (programInfos.padding) {
					// Get back the IV (16 first bytes of the message)
					iv = encryptor.getIvCBC(msg);
					System.out.println("1) msg.length = " + msg.length);
					// Copy msg value into a new string that is 16 bytes less wide
					msg = encryptor.getCiphertextProperLength(msg, iv.length);
					System.out.println("2) msg.length = " + msg.length);
				} else {
					BufferedReader reader = new BufferedReader(
							new FileReader(new File(Utilities.getCfgFile(programInfos.filesInput, "crypto_cfg"))));
					String line = reader.readLine();
					splited = line.split("\\s+");
					iv = splited[0].getBytes();
				}
				if (programInfos.integrity) {
					if (programInfos.padding) {
						System.out.println("3) msg.length = " + msg.length);
						hmacGetted = Arrays.copyOfRange(msg, msg.length - 64, msg.length);
						// remove the 64 last bytes from the message
						msg = Arrays.copyOfRange(msg, 0, msg.length - 64);

						// Decrypt msg
						output = encryptor.cipherCbc("Decrypt", msg, new IvParameterSpec(iv));
						// Erase the padding if there is some
						output = encryptor.removeBytesAdded(output);
					} else {
						hmacGetted = splited[1].getBytes();
						output = encryptor.cipherCts("Decrypt", msg, new IvParameterSpec(iv));
					}

				} else {
					// Decrypt msg
					output = encryptor.cipherCbc("Decrypt", msg, new IvParameterSpec(iv));
					// Erase the padding if there is some
					output = encryptor.removeBytesAdded(output);
				}

				// Question 6 :

				if (programInfos.integrity) {
					// Get the Hmac from the message (the last 64 bytes)
					byte[] hmac = encryptor.calculateHMAC(output, "9^%bNhi8Q^CQ#@G1%^5KX1fXT9Gl&x");
					if (Arrays.equals(hmac, hmacGetted))
						System.out.println("Intégrité vérifiée, le fichier n'a pas été altéré");
				}
			}

			utilities.bytesToFile(output, programInfos.fileOutput);

		} else {
			Path tmp = Paths.get(programInfos.fileOutput);
			String locationFolder = tmp.getParent().toString();
			System.out.println("folder =" + locationFolder);
			File file = new File(locationFolder + "/" + "tmp/");
			boolean bool = file.mkdir();

			for (int i = 0; i < programInfos.filesInput.size(); i++) {
				// FileTime creationTime = (FileTime) Files.getAttribute(fInput.toPath(),
				// "creationTime");
				File fInput = new File(programInfos.filesInput.get(i));
				String fileName = fInput.getName();

				encryptor.setKeyFromString(programInfos.key, "AES");

				byte[] msg = utilities.getBytesFromFile(programInfos.filesInput.get(i));

				byte[] output = null;
				if (programInfos.encryptionMode.equals("-enc")) {

					// Question 1
					// Generate a secure random IV
					iv = random.generateSeed(16);
					FileWriter writer = null;
					if (programInfos.padding) {
						output = encryptor.cipherCbc("Encrypt", msg, new IvParameterSpec(iv));
					}
					// Question 6
					else {
						File cfg = new File(new File(programInfos.fileOutput).getAbsolutePath() + "/crypto_cfg");
						writer = new FileWriter(cfg);
						writer.write(new String(new IvParameterSpec(iv).getIV()));
						output = encryptor.cipherCts("Encrypt", msg, new IvParameterSpec(iv));

					}
					if (programInfos.integrity) {
						byte[] hmac = encryptor.calculateHMAC(msg, "9^%bNhi8Q^CQ#@G1%^5KX1fXT9Gl&x");
						if (!programInfos.padding)
							writer.write(" " + new String(hmac));
						else {
							byte[] msgFinal = new byte[iv.length + output.length + hmac.length];
							System.arraycopy(iv, 0, msgFinal, 0, iv.length);
							System.arraycopy(output, 0, msgFinal, iv.length, output.length);
							System.arraycopy(hmac, 0, msgFinal, iv.length + output.length, hmac.length);
							output = msgFinal;
						}

					} else {
						byte[] msgFinal = new byte[iv.length + output.length];
						System.arraycopy(iv, 0, msgFinal, 0, iv.length);
						System.arraycopy(output, 0, msgFinal, iv.length, output.length);
						output = msgFinal;
					}
					if(!programInfos.padding) {
						writer.write("\n");
						writer.close();
					}
				} else {
					// Question 1 :
					byte[] hmacGetted = null;
					String[] splited = null;
					if (programInfos.padding) {
						// Get back the IV (16 first bytes of the message)
						iv = encryptor.getIvCBC(msg);
						System.out.println("1) msg.length = " + msg.length);
						// Copy msg value into a new string that is 16 bytes less wide
						msg = encryptor.getCiphertextProperLength(msg, iv.length);
						System.out.println("2) msg.length = " + msg.length);
					} else {
						BufferedReader reader = new BufferedReader(
								new FileReader(new File(Utilities.getCfgFile(programInfos.filesInput, "crypto_cfg"))));
						String line = reader.readLine();
						splited = line.split("\\s+");
						iv = splited[0].getBytes();
					}
					if (programInfos.integrity) {

						if (programInfos.padding) {
							System.out.println("3) msg.length = " + msg.length);
							hmacGetted = Arrays.copyOfRange(msg, msg.length - 64, msg.length);
							// remove the 64 last bytes from the message
							msg = Arrays.copyOfRange(msg, 0, msg.length - 64);

							// Decrypt msg
							output = encryptor.cipherCbc("Decrypt", msg, new IvParameterSpec(iv));
							// Erase the padding if there is some
							output = encryptor.removeBytesAdded(output);
						} else {
							hmacGetted = splited[1].getBytes();
							output = encryptor.cipherCts("Decrypt", msg, new IvParameterSpec(iv));
						}

					} else {
						// Decrypt msg
						output = encryptor.cipherCbc("Decrypt", msg, new IvParameterSpec(iv));
						// Erase the padding if there is some
						output = encryptor.removeBytesAdded(output);
					}
					if (programInfos.integrity) {
						byte[] hmac = encryptor.calculateHMAC(output, "9^%bNhi8Q^CQ#@G1%^5KX1fXT9Gl&x");
						if (Arrays.equals(hmac, hmacGetted))
							System.out.println("Intégrité vérifiée pour le fichier " + fileName
									+ ", le fichier n'a pas été altéré");
					}
				}
				utilities.bytesToFile(output, locationFolder + "/" + "tmp/" + fileName);
			}

			Utilities.pack(locationFolder + "/" + "tmp/", programInfos.fileOutput + ".zip");
			for (int i = 0; i < programInfos.filesInput.size(); i++) {
				File f = new File(programInfos.filesInput.get(i));
				String fileName = f.getName();
				f = new File(locationFolder + "/" + fileName);
				f.delete();
			}
			Utilities.deleteFolder(locationFolder + "/" + "tmp/");
		}
	}
}
