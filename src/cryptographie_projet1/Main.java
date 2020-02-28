package cryptographie_projet1;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.spec.IvParameterSpec;
import javax.swing.JFrame;
import javax.swing.JOptionPane;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;

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
			byte[] output_cts = null;
			byte[] config_file = null;

			// Encryption Mode
			if (programInfos.encryptionMode.equals("-enc")) {
				// Generate a secure random IV
				iv = random.generateSeed(16);

				if (programInfos.padding) {
					output = encryptor.cipherCbc("Encrypt", msg, new IvParameterSpec(iv));
				} else {
					output = new byte[msg.length];
					output_cts = encryptor.cipherCts("Encrypt", msg, new IvParameterSpec(iv));
					System.arraycopy(output_cts, 0, output, 0, msg.length);
				}
				if (programInfos.integrity) {
					// Create OMAC for the integrity
					BlockCipher cipher = new AESEngine();
					CMac cmac = new CMac(cipher);
					cmac.init(new KeyParameter(encryptor.getKey().getEncoded()));

					cmac.update(msg, 0, msg.length);
					byte[] omac = new byte[cmac.getMacSize()];
					cmac.doFinal(omac, 0);

					if (!programInfos.padding) {
						// Add IV and OMAC to the config file
						config_file = new byte[iv.length + omac.length];
						System.arraycopy(iv, 0, config_file, 0, iv.length);
						System.arraycopy(omac, 0, config_file, iv.length, omac.length);
					} else {
						byte[] msgFinal = new byte[iv.length + output.length + omac.length];
						// Add IV at the begining of the final message
						System.arraycopy(iv, 0, msgFinal, 0, iv.length);
						System.arraycopy(output, 0, msgFinal, iv.length, output.length);
						// Add OMAC at the end of the final message
						System.arraycopy(omac, 0, msgFinal, iv.length + output.length, omac.length);
						output = msgFinal;
					}
				} else {
					if (!programInfos.padding) {
						// Add only the IV on the config file (because user don't want to check
						// Integrity)
						config_file = new byte[iv.length];
						System.arraycopy(iv, 0, config_file, 0, iv.length);
					} else {
						// Add only the IV at the begining of the message (because user don't want to
						// check Integrity)
						byte[] msgFinal = new byte[iv.length + output.length];
						System.arraycopy(iv, 0, msgFinal, 0, iv.length);
						System.arraycopy(output, 0, msgFinal, iv.length, output.length);
						output = msgFinal;
					}
				}
				if (!programInfos.padding) {
					utilities.bytesToFile(config_file,
							new File(programInfos.fileOutput).getParent().toString() + "/crypto_cfg");
				}
			}
			// Decryption
			else {
				byte[] omacGetted = new byte[16];
				if (programInfos.padding) {
					// Get back the IV (16 first bytes of the message)
					iv = encryptor.getIvCBC(msg);
					// Copy msg value into a new string that is 16 bytes less wide
					msg = encryptor.getCiphertextProperLength(msg, iv.length);
				} else {
					// Get the IV from the config file
					config_file = utilities
							.getBytesFromFile(new File(programInfos.fileOutput).getParent().toString() + "/crypto_cfg");
					System.arraycopy(config_file, 0, iv, 0, iv.length);
				}
				if (programInfos.integrity) {
					if (programInfos.padding) {
						// Get the OMAC by taking the 64 last bytes of the message
						
						omacGetted = Arrays.copyOfRange(msg, msg.length - 16, msg.length);
						// remove the 64 last bytes from the message
						msg = Arrays.copyOfRange(msg, 0, msg.length - 16);
						// Decryption of the message
						output = encryptor.cipherCbc("Decrypt", msg, new IvParameterSpec(iv));
						// Erase the padding if there is some
						output = encryptor.removeBytesAdded(output);
					} else {
						// Get the OMAC from the config file
						System.arraycopy(config_file, iv.length, omacGetted, 0, config_file.length - iv.length);
						output = encryptor.cipherCts("Decrypt", msg, new IvParameterSpec(iv));
					}

				} else {
					if (programInfos.padding) {
						output = encryptor.cipherCbc("Decrypt", msg, new IvParameterSpec(iv));
						// Erase the padding if there is some
						output = encryptor.removeBytesAdded(output);
					} else {
						output = encryptor.cipherCts("Decrypt", msg, new IvParameterSpec(iv));
					}
				}
				if (programInfos.integrity) {
					BlockCipher cipher = new AESEngine();
					CMac cmac = new CMac(cipher);
					cmac.init(new KeyParameter(encryptor.getKey().getEncoded()));
					if (!programInfos.padding) {
						byte[] final_output_cts = output;
						output = new byte[msg.length];
						System.arraycopy(final_output_cts, 0, output, 0, msg.length);
					}
					cmac.update(output, 0, output.length);
					byte[] cmac_val = new byte[cmac.getMacSize()];
					cmac.doFinal(cmac_val, 0);

					// Get the OMAC from the decrypted message
					JFrame frame;
					frame = new JFrame();
					// Compare the OMAC get from the message / config file and the one that has just
					// been calculated to see if there was any integrity problem on the file
					if (Arrays.equals(cmac_val, omacGetted)) {
						JOptionPane.showMessageDialog(frame,
								"L'integrite du fichier est verifee, le fichier n'a pas ete altere");
					} else {
						JOptionPane.showMessageDialog(frame,
								"L'integrite du fichier n'est pas verifee, le fichier a ete altere !!!");
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

					if (programInfos.padding) {
						output = encryptor.cipherCbc("Encrypt", msg, new IvParameterSpec(iv));
					} else {
						//output = new byte[msg.length];
						// output_cts = encryptor.cipherCts("Encrypt", msg, new IvParameterSpec(iv));
						// System.arraycopy(output_cts, 0, output, 0, msg.length);
					}
					if (programInfos.integrity) {
						// Create OMAC for the integrity
						BlockCipher cipher = new AESEngine();
						CMac cmac = new CMac(cipher);
						cmac.init(new KeyParameter(encryptor.getKey().getEncoded()));

						cmac.update(msg, 0, msg.length);
						byte[] omac = new byte[cmac.getMacSize()];
						cmac.doFinal(omac, 0);

						if (!programInfos.padding) {
							// Add IV and OMAC to the config file
							// config_file = new byte[iv.length + omac.length];
							// System.arraycopy(iv, 0, config_file, 0, iv.length);
							// System.arraycopy(omac, 0, config_file, iv.length, omac.length);
						} else {
							byte[] msgFinal = new byte[iv.length + output.length + omac.length];
							// Add IV at the begining of the final message
							System.arraycopy(iv, 0, msgFinal, 0, iv.length);
							System.arraycopy(output, 0, msgFinal, iv.length, output.length);
							// Add OMAC at the end of the final message
							System.arraycopy(omac, 0, msgFinal, iv.length + output.length, omac.length);
							output = msgFinal;
						}
					} else {
						if (!programInfos.padding) {
							// Add only the IV on the config file (because user don't want to check
							// Integrity)
							// config_file = new byte[iv.length];
							// System.arraycopy(iv, 0, config_file, 0, iv.length);
						} else {
							// Add only the IV at the begining of the message (because user don't want to
							// check Integrity)
							byte[] msgFinal = new byte[iv.length + output.length];
							System.arraycopy(iv, 0, msgFinal, 0, iv.length);
							System.arraycopy(output, 0, msgFinal, iv.length, output.length);
							output = msgFinal;
						}
					}
					if (!programInfos.padding) {
						// utilities.bytesToFile(config_file, new
						// File(programInfos.fileOutput).getParent().toString() + "/crypto_cfg");
					}
				}
				// Decryption
				else {
					byte[] omacGetted = new byte[16];
					if (programInfos.padding) {
						// Get back the IV (16 first bytes of the message)
						iv = encryptor.getIvCBC(msg);
						// Copy msg value into a new string that is 16 bytes less wide
						msg = encryptor.getCiphertextProperLength(msg, iv.length);
					} else {
						// Get the IV from the config file
						// config_file = utilities.getBytesFromFile(new
						// File(programInfos.fileOutput).getParent().toString() + "/crypto_cfg");
						// System.arraycopy(config_file, 0, iv, 0, iv.length);
					}
					if (programInfos.integrity) {
						if (programInfos.padding) {
							// Get the OMAC by taking the 64 last bytes of the message
							// omacGetted = Arrays.copyOfRange(msg, msg.length - 64, msg.length);
							omacGetted = Arrays.copyOfRange(msg, msg.length - 16, msg.length);
							// remove the 64 last bytes from the message
							msg = Arrays.copyOfRange(msg, 0, msg.length - 16);
							// Decryption of the message
							output = encryptor.cipherCbc("Decrypt", msg, new IvParameterSpec(iv));
							// Erase the padding if there is some
							output = encryptor.removeBytesAdded(output);
						} else {
							// Get the OMAC from the config file
							// System.arraycopy(config_file, iv.length, omacGetted, 0, config_file.length -
							// iv.length);
							// output = encryptor.cipherCts("Decrypt", msg, new IvParameterSpec(iv));
						}

					} else {
						if (programInfos.padding) {
							output = encryptor.cipherCbc("Decrypt", msg, new IvParameterSpec(iv));
							// Erase the padding if there is some
							output = encryptor.removeBytesAdded(output);
						} else {
							output = encryptor.cipherCts("Decrypt", msg, new IvParameterSpec(iv));
						}
					}
					if (programInfos.integrity) {
						BlockCipher cipher = new AESEngine();
						CMac cmac = new CMac(cipher);
						cmac.init(new KeyParameter(encryptor.getKey().getEncoded()));
						if (!programInfos.padding) {
							byte[] final_output_cts = output;
							output = new byte[msg.length];
							System.arraycopy(final_output_cts, 0, output, 0, msg.length);
						}
						cmac.update(output, 0, output.length);
						byte[] cmac_val = new byte[cmac.getMacSize()];
						cmac.doFinal(cmac_val, 0);

						// Get the OMAC from the decrypted message
						JFrame frame;
						frame = new JFrame();
						// Compare the OMAC get from the message / config file and the one that has just
						// been calculated to see if there was any integrity problem on the file
						if (Arrays.equals(cmac_val, omacGetted)) {
							JOptionPane.showMessageDialog(frame,
									"L'integrite du fichier est verifiee, le fichier n'a pas ete altere");
						} else {
							JOptionPane.showMessageDialog(frame,
									"L'integrite du fichier n'est pas verifiee, le fichier a ete altere !!!");
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
