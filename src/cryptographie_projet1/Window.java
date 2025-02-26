package cryptographie_projet1;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.File;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTextField;

public class Window {

	private JFrame frame;
	private JTextField outputNameInput;
	private JTextField keyInput;

	private ProgramInformations programinformations = new ProgramInformations();
	private DefaultListModel listModel = new DefaultListModel();

	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					Window window = new Window();
					window.frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	public Window() {
		initialize();
		this.listModel.addElement("Vos fichiers apparaitrons ici");
	}

	private void initialize() {
		frame = new JFrame();
		frame.setBounds(100, 100, 600, 300);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(new BorderLayout(0, 0));

		JPanel panel = new JPanel();
		frame.getContentPane().add(panel, BorderLayout.SOUTH);

		JPanel panel_1 = new JPanel();
		frame.getContentPane().add(panel_1, BorderLayout.NORTH);

		JLabel lblNewLabel = new JLabel("Chemin du fichier de sortie :");

		outputNameInput = new JTextField();
		outputNameInput.setColumns(10);

		JLabel lblNewLabel2 = new JLabel("Cle de chiffrement : ");

		keyInput = new JTextField();
		keyInput.setColumns(10);

		JPanel panel_3 = new JPanel();
		panel_3.setBackground(new Color(192, 192, 192));
		frame.getContentPane().add(panel_3, BorderLayout.WEST);
		panel_3.setLayout(new BoxLayout(panel_3, BoxLayout.Y_AXIS));

		Box b1 = Box.createHorizontalBox();
		Box b2 = Box.createHorizontalBox();

		JList listOutput = new JList(listModel);
		listOutput.setBackground(new Color(192, 192, 192));

		listOutput.setVisibleRowCount(1);
		JScrollPane scrollPane_1 = new JScrollPane(listOutput);
		Dimension d = panel_3.getPreferredSize();
		d.width = 200;
		scrollPane_1.setPreferredSize(d);
		panel_3.add(scrollPane_1);
		
		JButton deleteItemButton = new JButton("Supprimer l'item");
		deleteItemButton.setVisible(false);
		deleteItemButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int selectedIndex = listOutput.getSelectedIndex();
				if (selectedIndex == -1) {
					JOptionPane.showMessageDialog(frame,
							"Veuillez selectionner un fichier avant de pouvoir le supprimer");
				} else {
					programinformations.filesInput.remove(selectedIndex);
					listModel.remove(selectedIndex);
					if (programinformations.filesInput.size() == 0) {
						deleteItemButton.setVisible(false);
						listModel.addElement("Vos fichiers apparaitrons ici");
					}
				}
			}
		});
		b1.add(deleteItemButton);
		b1.add(Box.createHorizontalGlue());

		JButton addFilesBtn = new JButton("Ajouter fichier(s)");
		addFilesBtn.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser chooser = new JFileChooser();
				chooser.setMultiSelectionEnabled(true);
				chooser.showOpenDialog(frame);
				File[] files = chooser.getSelectedFiles();
				if (listModel.size() > 0 && listModel.get(0) == "Vos fichiers apparaitrons ici") {
					listModel.remove(0);
				}
				for (int i = 0; i < files.length; i++) {
					programinformations.filesInput.add(files[i].toString());
					listModel.addElement(files[i].toString());
				}
				deleteItemButton.setVisible(true);
			}
		});

		b2.add(addFilesBtn);
		b2.add(Box.createHorizontalGlue());
		panel_3.add(b2);
		panel_3.add(b1);
		panel_1.add(lblNewLabel2);
		panel_1.add(keyInput);

		panel_1.add(lblNewLabel);
		panel_1.add(outputNameInput);

		JPanel panel_2 = new JPanel();
		frame.getContentPane().add(panel_2, BorderLayout.EAST);
		panel_2.setLayout(new BoxLayout(panel_2, BoxLayout.Y_AXIS));

		ButtonGroup bg = new ButtonGroup();

		JRadioButton paddingRadioButton = new JRadioButton("Padding");
		bg.add(paddingRadioButton);
		panel_2.add(paddingRadioButton);

		JRadioButton withoutPaddingRadioButton = new JRadioButton("Mode CTS");
		bg.add(withoutPaddingRadioButton);
		panel_2.add(withoutPaddingRadioButton);

		paddingRadioButton.setSelected(true);
		paddingRadioButton.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent itemEvent) {
				programinformations.padding = paddingRadioButton.isSelected();
			}
		});
		programinformations.padding = paddingRadioButton.isSelected();

		JCheckBox integrityCheckBox = new JCheckBox("Integrite");
		integrityCheckBox.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent itemEvent) {
				programinformations.integrity = integrityCheckBox.isSelected();
			}
		});
		panel_2.add(integrityCheckBox);
		programinformations.integrity = false;

		JButton encryptButton = new JButton("Chiffrer");
		encryptButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				programinformations.encryptionMode = "-enc";
				programinformations.fileOutput = outputNameInput.getText();
				programinformations.key = keyInput.getText();
				if (programinformations.key.contentEquals("")) {
					JOptionPane.showMessageDialog(frame, "La cle de chiffement ne peut etre vide");
				} else if (programinformations.fileOutput.contentEquals("")) {
					JOptionPane.showMessageDialog(frame, "Le chemin de sortie du fichier ne peut etre vide");
				} else if (programinformations.filesInput.size() <= 0) {
					JOptionPane.showMessageDialog(frame, "Aucun fichiers en entree");
				}  else if(!programinformations.padding && programinformations.filesInput.size() > 1) {
					JOptionPane.showMessageDialog(frame,"Vous ne pouvez pas chiffrer plusieurs fichier en mode CTS");
				} else {
					
					for (int i = 0; i < programinformations.filesInput.size(); i++) {
						if (Utilities.getNumberBytesFile(programinformations.filesInput.get(i)) <= 16 && !programinformations.padding) {
							int res = JOptionPane.showOptionDialog(frame,
									"Le fichier d'entree -in " + programinformations.filesInput.get(i)
											+ " est trop court pour utiliser le CTS",
									"Erreur", JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE, null, null,
									null);
							if (res == JOptionPane.OK_OPTION) {
								System.exit(0);
							}
						}
						verifyFileDoesNotExists(programinformations.fileOutput, frame);
						verifyFileExists(programinformations.filesInput.get(i), frame);
					}
					try {
						Main.main(programinformations);
					} catch (Exception e1) {
						e1.printStackTrace();
					}
				}
			}
		});
		panel.add(encryptButton);

		JButton decryptButton = new JButton("Dechiffrer");
		decryptButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				programinformations.encryptionMode = "-dec";
				programinformations.fileOutput = outputNameInput.getText();
				programinformations.key = keyInput.getText();
				if (programinformations.key.contentEquals("")) {
					JOptionPane.showMessageDialog(frame, "La cle de chiffement ne peut etre vide");
				} else if (programinformations.fileOutput.contentEquals("")) {
					JOptionPane.showMessageDialog(frame, "Le chemin de sortie du fichier ne peut etre vide");
				} else if (programinformations.filesInput.size() <= 0) {
					JOptionPane.showMessageDialog(frame, "Aucun fichiers en entree");
				} else if(!programinformations.padding && programinformations.filesInput.size() > 1) {
					JOptionPane.showMessageDialog(frame,"Vous ne pouvez pas dechiffrer plusieurs fichier en mode CTS");
				} else if ((!programinformations.padding && programinformations.filesInput.size() == 1)
						|| (!programinformations.padding && programinformations.filesInput.size() > 1
								&& !Utilities.verifieCTS(programinformations.filesInput, "crypto_cfg"))) {
					while (!new File(programinformations.fileCfg).getName().equals("crypto_cfg")) {
						JOptionPane.showMessageDialog(frame,
								"Le fichier crypto est obligatoire en CTS, merci de le selectionner");
						JFileChooser chooser = new JFileChooser();
						chooser.setMultiSelectionEnabled(true);
						chooser.showOpenDialog(frame);
						programinformations.fileCfg = chooser.getSelectedFile().toString();
					}
					execProgram();
				} else {
					execProgram();
				}
			}
		});
		panel.add(decryptButton);
	}

	private void verifyFileDoesNotExists(String location, JFrame frame) {
		File f = new File(location);
		if (f.isDirectory())
			JOptionPane.showMessageDialog(frame, "Le chemin de sortie \" + location + \" de sortie est un dossier");
		if (f.exists()) {
			int dialogResult = JOptionPane.showConfirmDialog(frame,
					"Le fichier de sortie existe deja, voulez-vous l'ecraser ?", "Existe", JOptionPane.YES_NO_OPTION,
					JOptionPane.QUESTION_MESSAGE);

			if (dialogResult == JOptionPane.NO_OPTION) {
				int res = JOptionPane.showOptionDialog(null,
						"Le chemin de sortie -out " + location
								+ " existe deja et vous n'avez pas autorise le programme a ecraser le fichier",
						"Erreur", JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE, null, null, null);
				if (res == JOptionPane.OK_OPTION) {
					System.exit(0);
				}
			}
		}
	}

	private void verifyFileExists(String location, JFrame frame) {
		File f = new File(location);
		if (!f.exists()) {
			int res = JOptionPane.showOptionDialog(null, "Le chemin d'entree -in " + location + " n'existe pas",
					"Erreur", JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE, null, null, null);
			if (res == JOptionPane.OK_OPTION) {
				System.exit(0);
			}
		}
		if (f.isDirectory()) {
			int res = JOptionPane.showOptionDialog(null, "Le chemin d'entree -in " + location + " est un dossier",
					"Erreur", JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE, null, null, null);
			if (res == JOptionPane.OK_OPTION) {
				System.exit(0);
			}
		}
		if (Utilities.getFileExtension(f).equals("zip")) {
			int res = JOptionPane.showOptionDialog(null,
					"Le chemin d'entree " + location
							+ " est une archive, vous devez la decompresser et ajouter les fichiers manuellement.",
					"Erreur", JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE, null, null, null);
			if (res == JOptionPane.OK_OPTION) {
				System.exit(0);
			}
		}
	}

	private void execProgram() {
		verifyFileDoesNotExists(programinformations.fileOutput, frame);
		for (int i = 0; i < programinformations.filesInput.size(); i++) {
			verifyFileExists(programinformations.filesInput.get(i), frame);
		}
		try {
			Main.main(programinformations);
		} catch (Exception e1) {
			e1.printStackTrace();
		}
	}
}
