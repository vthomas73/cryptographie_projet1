package cryptographie_projet1;

import java.io.File;
import java.util.Scanner;

public class Utilities {

	public void verifArgs(String[] args) throws Exception {
		if (args.length <= 0)
			throw new Exception(
					"Parametres requis : \nfilecrypt –enc|-dec –key K...K –in <input file> -out <output file>");
		if (!args[0].equals("-enc") && !args[0].equals("-dec"))
			throw new Exception("Le premier argument doit être : –enc|-dec");
		if (args.length < 2 || !args[1].equals("-key"))
			throw new Exception("Le deuxième argument doit être : –key");
		if (args.length < 3)
			throw new Exception("Le troisième argument doit être la clé K...K");
		verifyHexa(args[2]);
		if (args.length < 4 || !args[3].equals("-in"))
			throw new Exception("Le quatrième argument doit être : –in");
		if (args.length < 5)
			throw new Exception("Le cinquième argument doit être le chemin d'entrée <input file>");
		verifyFileExists(args[4]);
		if (args.length < 6 || !args[5].equals("-out"))
			throw new Exception("Le sixième argument doit être : –out");
		if (args.length < 7)
			throw new Exception("Le septième argument doit être le chemin de sortie <output file>");
		verifyFileDoesNotExists(args[6]);
	}

	private void verifyHexa(String key) throws Exception {
		boolean isHex = key.matches("[0-9|a-f|A-F]*");
		if (key.length() != 32 && key.length() != 48 && key.length() != 64)
			throw new Exception("La clé n'est pas codée sur 128/192 ou 254 bits !");
		if (!isHex)
			throw new Exception("La clé n'est pas au format hexadécimal");
	}

	private void verifyFileExists(String location) throws Exception {
		File f = new File(location);
		if (!f.exists()) {
			throw new Exception("Le chemin d'entrée -in n'existe pas");
		}
		if (f.isDirectory())
			throw new Exception("Le chemin d'entrée -in est un dossier");
	}

	private void verifyFileDoesNotExists(String location) throws Exception {
		System.out.println(location);
		File f = new File(location);
		if (f.isDirectory())
			throw new Exception("Le chemin de sortie -out est un dossier");
		if (f.exists()) {
			System.out.print("Le fichier existe déja, voulez-vous l'écraser ? Yes/No\n");
			Scanner scanner = new Scanner(System.in);
			String inputString = scanner.nextLine();
			scanner.close();
			if (!inputString.toLowerCase().equals("yes"))
				throw new Exception(
						"Le chemin de sortie -out existe déja et vous n'avez pas autorisé le programme à écraser le fichier");
		}
	}
}
