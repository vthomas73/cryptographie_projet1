package cryptographie_projet1;

public class Main {

	public static void main(String[] args) throws Exception {
		Utilities utilities = new Utilities();
		utilities.verifArgs(args);
		Encryptor encryptor = new Encryptor();
		encryptor.setRandomKey("AES");
	}
}
