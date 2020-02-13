package cryptographie_projet1;

import java.util.ArrayList;
import java.util.List;

public class ProgramInformations {
	public List<String> filesInput = new ArrayList<String>();
	public String fileOutput;
	public String key;

	public void addInputFile(String location) {
		filesInput.add(location);
	}

	public void setKey(String key) {
		this.key = key;
	}

	public void setOutputFile(String location) {
		this.fileOutput = location;
	}
}
