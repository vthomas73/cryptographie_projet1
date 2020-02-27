package cryptographie_projet1;

import java.util.ArrayList;
import java.util.List;

public class ProgramInformations {
	public List<String> filesInput = new ArrayList<String>();
	public String fileOutput;
	public String key;
	public String encryptionMode;
	public boolean padding;
	public boolean integrity;

	public void addInputFile(String location) {
		filesInput.add(location);
	}

	public void setKey(String key) {
		this.key = key;
	}

	public void setOutputFile(String location) {
		this.fileOutput = location;
	}
	public String toString() {
		String str = "Padding = " + this.padding;
		str += " intégrité = " + this.integrity;
		str += " encryptionMode = " + this.encryptionMode;
		str += " key = " + this.key;
		str += " fileOutput = " + this.fileOutput;
		for (int i = 0 ; i < filesInput.size() ; i++) {
			str += " fileInput " + i + " = " + this.filesInput.get(i);
		}
		return str;
	}
}
