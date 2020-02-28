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
import javax.swing.JFrame;
import javax.swing.JOptionPane;

public class Main {

	public static void main(ProgramInformations programInfos) throws Exception {
		Utilities utilities = new Utilities();
		Encryptor encryptor = new Encryptor();
		SecureRandom random = new SecureRandom();
		byte[] iv = new byte[16];

		if (programInfos.filesInput.size() == 1) {
			File fInput = new File(programInfos.filesInput.get(0));
			String fileNameInput = fInput.getName();
			File fOutput = new File(programInfos.fileOutput);
			String fileNameOutput = fOutput.getName();
			encryptor.setKeyFromString(programInfos.key, "AES");
			byte[] msg = utilities.getBytesFromFile(programInfos.filesInput.get(0));
			byte[] output = null;
			byte[] config_file = null;
			
			// Encryption Mode
			if (programInfos.encryptionMode.equals("-enc")) {

				// Generate a secure random IV
				iv = random.generateSeed(16);
				
				if (programInfos.padding) {
					output = encryptor.cipherCbc("Encrypt", msg, new IvParameterSpec(iv));
				}
				else {
					output = encryptor.cipherCts("Encrypt", msg, new IvParameterSpec(iv));
				}
				if (programInfos.integrity) {
					// Create hmac for the integrity
					byte[] hmac = encryptor.calculateHMAC(msg, "9^%bNhi8Q^CQ#@G1%^5KX1fXT9Gl&x");
					if (!programInfos.padding) {
						// Add IV and hmac to the config file
						config_file = new byte[iv.length + hmac.length];
						System.arraycopy(iv, 0, config_file, 0, iv.length);
						System.arraycopy(hmac, 0, config_file, iv.length, hmac.length);
					}
					else {
						byte[] msgFinal = new byte[iv.length + output.length + hmac.length];
						// Add IV at the begining of the final message
						System.arraycopy(iv, 0, msgFinal, 0, iv.length);
						System.arraycopy(output, 0, msgFinal, iv.length, output.length);
						// Add hmac at the end of the final message
						System.arraycopy(hmac, 0, msgFinal, iv.length + output.length, hmac.length);
						output = msgFinal;
					}
				} else {
					if(!programInfos.padding) {
						//Add only the IV on the config file (because user don't want to check Integrity)
						config_file = new byte[iv.length];
						System.arraycopy(iv, 0, config_file, 0, iv.length);
					}
					else {
						//Add only the IV at the begining of the message (because user don't want to check Integrity)
						byte[] msgFinal = new byte[iv.length + output.length];
						System.arraycopy(iv, 0, msgFinal, 0, iv.length);
						System.arraycopy(output, 0, msgFinal, iv.length, output.length);
						output = msgFinal;
					}
				}
				if(!programInfos.padding) {
					utilities.bytesToFile(config_file, new File(programInfos.fileOutput).getParent().toString() + "/crypto_cfg");
				}
			} 
			// Decryption
			else {
				byte[] hmacGetted = new byte[64];
				if (programInfos.padding) {
					// Get back the IV (16 first bytes of the message)
					iv = encryptor.getIvCBC(msg);
					// Copy msg value into a new string that is 16 bytes less wide
					msg = encryptor.getCiphertextProperLength(msg, iv.length);
				} else {
					//Get the IV from the config file
					config_file = utilities.getBytesFromFile(new File(programInfos.fileOutput).getParent().toString() + "/crypto_cfg");
					System.arraycopy(config_file, 0, iv, 0, iv.length);
				}
				if (programInfos.integrity) {
					if (programInfos.padding) {
						// Get the hmac by taking the 64 last bytes of the message
						hmacGetted = Arrays.copyOfRange(msg, msg.length - 64, msg.length);
						// remove the 64 last bytes from the message
						msg = Arrays.copyOfRange(msg, 0, msg.length - 64);
						// Decryption of the message
						output = encryptor.cipherCbc("Decrypt", msg, new IvParameterSpec(iv));
						// Erase the padding if there is some
						output = encryptor.removeBytesAdded(output);
					} else {
						// Get the hmac from the config file
						System.arraycopy(config_file, iv.length, hmacGetted, 0, config_file.length - iv.length);
						output = encryptor.cipherCts("Decrypt", msg, new IvParameterSpec(iv));
					}

				} else {
					if(programInfos.padding) {
						output = encryptor.cipherCbc("Decrypt", msg, new IvParameterSpec(iv));
						// Erase the padding if there is some
						output = encryptor.removeBytesAdded(output);
					}
					else {
						output = encryptor.cipherCts("Decrypt", msg, new IvParameterSpec(iv));
					}
				}
				if (programInfos.integrity) {
					// Get the Hmac from the decrypted message
					byte[] hmac = encryptor.calculateHMAC(output, "9^%bNhi8Q^CQ#@G1%^5KX1fXT9Gl&x");
					JFrame frame;
					frame = new JFrame();
					//Compare the hmac get from the message / config file and the one that has just been calculated to see if there was any integrity problem on the file
					if (Arrays.equals(hmac, hmacGetted)) {
						 JOptionPane.showMessageDialog(frame, "L'intégrité du fichier est vérifiée, le fichier n'a pas été altéré");
					}
					else {
						 JOptionPane.showMessageDialog(frame, "L'intégrité du fichier n'est pas vérifiée, le fichier a été altéré !!!");
					}
				}
			}

			utilities.bytesToFile(output, programInfos.fileOutput);

		} 
		// If there is more than 1 file
		else {
			// Creation of a temporary local folder to store the file
			Path tmp = Paths.get(programInfos.fileOutput);
			String locationFolder = tmp.getParent().toString();
			System.out.println("folder =" + locationFolder);
			File file = new File(locationFolder + "/" + "tmp/");
			boolean bool = file.mkdir();
			
			// iterate for each file
			for (int i = 0; i < programInfos.filesInput.size(); i++) {
				File fInput = new File(programInfos.filesInput.get(i));
				String fileName = fInput.getName();

				encryptor.setKeyFromString(programInfos.key, "AES");

				byte[] msg = utilities.getBytesFromFile(programInfos.filesInput.get(i));

				byte[] output = null;
				if (programInfos.encryptionMode.equals("-enc")) {

					// Generate a secure random IV
					iv = random.generateSeed(16);
					FileWriter writer = null;
					if (programInfos.padding) {
						output = encryptor.cipherCbc("Encrypt", msg, new IvParameterSpec(iv));
					}
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
						/*writer.write("\n");
						writer.close();*/
					}
				} else {
					byte[] hmacGetted = new byte[64];
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
						JFrame frame;
						frame = new JFrame();
						if (Arrays.equals(hmac, hmacGetted)) {
							 JOptionPane.showMessageDialog(frame, "L'intégrité du fichier est vérifiée, le fichier n'a pas été altéré");
						}
						else {
							 JOptionPane.showMessageDialog(frame, "L'intégrité du fichier n'est pas vérifiée, le fichier a été altéré !!!");
						}
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
