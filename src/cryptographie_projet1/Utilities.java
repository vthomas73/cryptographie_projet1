package cryptographie_projet1;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.List;
import java.util.Scanner;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Utilities {

	public ProgramInformations verifArgs(String[] args) throws Exception {
		if (args.length <= 0)
			throw new Exception(
					"Parametres requis : \nfilecrypt -enc|-dec -key K...K in <input file> [<input file> ... ] -out <output file>");
		ProgramInformations programInfos = new ProgramInformations();
		int nbFileList = args.length - 7;
		if (!args[0].equals("-enc") && !args[0].equals("-dec"))
			throw new Exception("Le premier argument doit �tre : -enc|-dec");
		programInfos.encryptionMode = args[0];
		if (args.length < 2 || !args[1].equals("-key"))
			throw new Exception("Le deuxi�me argument doit �tre : -key");
		if (args.length < 3)
			throw new Exception("Le troisi�me argument doit �tre la cl� K...K");
		verifyHexa(args[2]);
		programInfos.setKey(args[2]);
		if (args.length < 4 || !args[3].equals("-in"))
			throw new Exception("Le quatrième argument doit �tre : -in");
		if (args.length < 5)
			throw new Exception("Le cinqui�me argument doit �tre le chemin d'entr�e <input file>");
		verifyFileExists(args[4]);
		programInfos.addInputFile(args[4]);
		for (int i = 0; i < nbFileList; i++) {
			verifyFileExists(args[4 + i + 1]);
			programInfos.addInputFile(args[4 + i + 1]);
		}
		if (args.length < 6 + nbFileList || !args[5 + nbFileList].equals("-out"))
			throw new Exception("Le sixi�me argument doit �tre : -out");
		if (args.length < 7 + nbFileList)
			throw new Exception("Le septi�me argument doit �tre le chemin de sortie <output file>");
		verifyFileDoesNotExists(args[6 + nbFileList]);
		programInfos.setOutputFile(args[6 + nbFileList]);
		return programInfos;
	}

	private void verifyHexa(String key) throws Exception {
		boolean isHex = key.matches("[0-9|a-f|A-F]*");
		if (key.length() != 32 && key.length() != 48 && key.length() != 64)
			throw new Exception("La cl� n'est pas cod�e sur 128/192 ou 254 bits !");
		if (!isHex)
			throw new Exception("La cl� n'est pas au format hexad�cimal");
	}

	private void verifyFileExists(String location) throws Exception {
		File f = new File(location);
		if (!f.exists()) {
			throw new Exception("Le chemin d'entr�e -in " + location + " n'existe pas");
		}
		if (f.isDirectory())
			throw new Exception("Le chemin d'entr�e -in " + location + " n'est un dossier");
	}

	private void verifyFileDoesNotExists(String location) throws Exception {
		File f = new File(location);
		if (f.isDirectory())
			throw new Exception("Le chemin de sortie " + location + " -out est un dossier");
		if (f.exists()) {
			System.out.print("Le fichier existe d�ja, voulez-vous l'�craser ? Yes/No\n");
			Scanner scanner = new Scanner(System.in);
			String inputString = scanner.nextLine();
			scanner.close();
			if (!inputString.toLowerCase().equals("yes"))
				throw new Exception("Le chemin de sortie -out " + location
						+ " existe d�ja et vous n'avez pas autoris� le programme � �craser le fichier");
		}
	}

	public String convertBytesArrayToString(byte[] bytesarray) {
		String string = "";
		for (int i = 0; i < bytesarray.length; i++) {
			string += String.format("%8s", Integer.toBinaryString(bytesarray[i] & 0xFF)).replace(' ', '0');
		}
		return string;
	}

	public byte[] getBytesFromFile(String location) throws IOException {
		File file = new File(location);
		return Files.readAllBytes(file.toPath());
	}

	public void bytesToFile(byte[] bytes, String location) {
		File file = new File(location);
		try {
			OutputStream os = new FileOutputStream(file);
			os.write(bytes);
			os.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void pack(String sourceDirPath, String zipFilePath) throws IOException {
		Path p = Files.createFile(Paths.get(zipFilePath));
		try (ZipOutputStream zs = new ZipOutputStream(Files.newOutputStream(p))) {
			Path pp = Paths.get(sourceDirPath);
			Files.walk(pp).filter(path -> !Files.isDirectory(path)).forEach(path -> {
				ZipEntry zipEntry = new ZipEntry(pp.relativize(path).toString());
				try {
					zs.putNextEntry(zipEntry);
					Files.copy(path, zs);
					zs.closeEntry();
				} catch (IOException e) {
					System.err.println(e);
				}
			});
		}
	}

	public static void deleteFolder(String folder) {
		File index = new File(folder);
		String[] entries = index.list();
		for (String s : entries) {
			File currentFile = new File(index.getPath(), s);
			currentFile.delete();
		}
		index.delete();
	}

	public static boolean verifieCTS(List<String> list, String str) {
		for (int i = 0; i < list.size(); i++) {
			if (list.get(i).contains(str))
				return true;
		}
		return false;
	}

	public static String getCfgFile(List<String> list, String str) {
		for (int i = 0; i < list.size(); i++) {
			if (list.get(i).contains(str))
				return list.get(i);
		}
		return null;
	}

	public static String getFileExtension(File file) {
		String fileName = file.getName();
		if (fileName.lastIndexOf(".") != -1 && fileName.lastIndexOf(".") != 0)
			return fileName.substring(fileName.lastIndexOf(".") + 1);
		else
			return "";
	}

	public static long getNumberBytesFile(String file) {
		File newfile = new File(file);
		return newfile.length();
	}

}
