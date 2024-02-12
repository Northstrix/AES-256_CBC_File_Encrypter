/*
AES-256 CBC File Encrypter
Distributed under the MIT License
© Copyright Maxim Bortnikov 2024
For more information please visit
sourceforge.net/projects/aes-256-cbc-file-encrypter/
github.com/Northstrix/AES-256_CBC_File_Encrypter
*/
package File_Encrypter;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTarget;
import java.awt.dnd.DropTargetDropEvent;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

public class MainClass extends JFrame {
    private List<String> droppedFiles = new ArrayList<>();
    private JLabel selectedFilesLabel;
    private static byte[] encdeckey;// = new byte[32];
    private JPasswordField textField;
    
    public void derive_key_from_textfield() throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(textField.getText().getBytes());
        encdeckey = md.digest();
    }
    
    public void processFileList() {
        if (droppedFiles == null || droppedFiles.isEmpty()) {
            JOptionPane.showMessageDialog(null, "No Files Selected");
        } else {
            JFrame frame = new JFrame();
            frame.setTitle("Selected Files");
            JTable table = new JTable(droppedFiles.size(), 1);
            for (int i = 0; i < droppedFiles.size(); i++) {
                table.setValueAt(droppedFiles.get(i), i, 0);
            }
            JScrollPane scrollPane = new JScrollPane(table);
            frame.add(scrollPane);
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.pack();
            frame.setVisible(true);
        }
    }
    
    public void encryptFiles() throws Exception {
        if (droppedFiles == null || droppedFiles.isEmpty()) {
            JOptionPane.showMessageDialog(null, "No Files Selected");
        } else {
        	if(textField.getPassword().length != 0){
        		String inscr ="Encrypt " + droppedFiles.size();
        		if (droppedFiles.size() == 1)
        			inscr += " File?";
        		else
        			inscr += " Files?";
                int result = JOptionPane.showConfirmDialog(null, inscr, "Encryption Confirmation", JOptionPane.YES_NO_OPTION);
                if (result == JOptionPane.YES_OPTION) {
            		for (int i = 0; i < droppedFiles.size(); i++) {
            			byte[] fileBytes = encryptByteWithAES256CBC(Files.readAllBytes(Paths.get(droppedFiles.get(i))));
    	        		Path outputPath = Paths.get(droppedFiles.get(i) + ".encr");
    					Files.write(outputPath, fileBytes);
            		}
            		JOptionPane.showMessageDialog(null, "Done");
                } else if (result == JOptionPane.NO_OPTION) {
                	JOptionPane.showMessageDialog(null, "Enter the key");
                }
        	}
        	else {
        		JOptionPane.showMessageDialog(null, "Operation was cancelled by user");
        	}
        	
        }
    }
    
    public static byte[] encryptByteWithAES256CBC(byte[] input) throws Exception {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKeySpec key = new SecretKeySpec(encdeckey, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        byte[] encr_iv = encryptIVWithAES256ECB(iv);
        byte[] encrypted = cipher.doFinal(input);
        byte[] result = new byte[encr_iv.length + encrypted.length];
        System.arraycopy(encr_iv, 0, result, 0, encr_iv.length);
        System.arraycopy(encrypted, 0, result, encr_iv.length, encrypted.length);
        return result;
    }
    
    public static byte[] encryptIVWithAES256ECB(byte[] input) throws Exception {
    	SecretKeySpec key = new SecretKeySpec(encdeckey, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(input);
    }
    
    public void decryptFiles() throws Exception {
        if (droppedFiles == null || droppedFiles.isEmpty()) {
            JOptionPane.showMessageDialog(null, "No Files Selected");
        } else {
        	if(textField.getPassword().length != 0){
        		String inscr ="Decrypt " + droppedFiles.size();
        		if (droppedFiles.size() == 1)
        			inscr += " File?";
        		else
        			inscr += " Files?";
        				
                int result = JOptionPane.showConfirmDialog(null, inscr, "Decryption Confirmation", JOptionPane.YES_NO_OPTION);
                if (result == JOptionPane.YES_OPTION) {
            		for (int i = 0; i < droppedFiles.size(); i++) {
            			byte[] fileBytes = decryptByteWithAES256CBC(Files.readAllBytes(Paths.get(droppedFiles.get(i))));
            			
            			String outputPath;
            			if (droppedFiles.get(i).endsWith(".encr")) {
            				outputPath = droppedFiles.get(i).substring(0, droppedFiles.get(i).length() - 5);
            			}
            			else
            				outputPath = droppedFiles.get(i);
            			
    					Files.write(Paths.get(outputPath), fileBytes);
            		}
            		JOptionPane.showMessageDialog(null, "Done");
                } else if (result == JOptionPane.NO_OPTION) {
                	JOptionPane.showMessageDialog(null, "Enter the key");
                }
        	}
        	else {
        		JOptionPane.showMessageDialog(null, "Operation was cancelled by user");
        	}
        	
        }
    }
    
    public static byte[] decryptByteWithAES256CBC(byte[] sourceArray) throws Exception {
        byte[] iv = decryptIVWithAES256ECB(Arrays.copyOfRange(sourceArray, 0, 16));
        byte[] ciphertext = Arrays.copyOfRange(sourceArray, 16, sourceArray.length);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKeySpec key = new SecretKeySpec(encdeckey, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        byte[] decrypted = cipher.doFinal(ciphertext);
        return decrypted;
    }
    
    public static byte[] decryptIVWithAES256ECB(byte[] input) throws Exception {
    	SecretKeySpec key = new SecretKeySpec(encdeckey, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(input);
    }
    
    public MainClass() {
        Font segoeUiSemibold = new Font("Segoe UI Semibold", Font.PLAIN, 14);
        setTitle("AES-256 CBC File Encrypter");
        JPanel background = new JPanel();
        background.setBackground(Color.decode("#7B08A5"));
        setContentPane(background);

        JMenuBar menuBar = new JMenuBar();
        
        JMenu fileMenu = new JMenu("  File  ");
        JMenuItem selectFilesItem = new JMenuItem("Select Files");
        JMenuItem showSelectedFilesItem = new JMenuItem("Show Selected Files");
        JMenuItem quitItem = new JMenuItem("Quit");

        fileMenu.add(selectFilesItem);
        fileMenu.add(showSelectedFilesItem);
        fileMenu.add(quitItem);

        selectFilesItem.addActionListener((ActionListener) new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setMultiSelectionEnabled(true);
                fileChooser.showOpenDialog(null);
                droppedFiles.clear();
                File[] selectedFiles = fileChooser.getSelectedFiles();
                for (File file : selectedFiles) {
                	MainClass.this.droppedFiles.add(file.getPath());
                }
                selectedFilesLabel.setText("Selected Files: " + droppedFiles.size());
            }
        });
        
        showSelectedFilesItem.addActionListener((ActionListener) new ActionListener() {
            public void actionPerformed(ActionEvent e) {
            	processFileList();
            }
        });
        
        quitItem.addActionListener((ActionListener) new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                System.exit(0);
            }
        });

        menuBar.add(fileMenu);

        JMenu aboutMenu = new JMenu("  More  ");
        menuBar.add(aboutMenu);
        JMenuItem about_item = new JMenuItem("About");
        aboutMenu.add(about_item);
        about_item.addActionListener((ActionListener) new ActionListener() {
            public void actionPerformed(ActionEvent e) {
            	about_form();
            }
        });
        
        setJMenuBar(menuBar);
        
        JPanel container = new JPanel();
        container.setPreferredSize(new Dimension(600, 210));
        container.setBackground(Color.WHITE);
        container.setForeground(Color.decode("#2D2D2D")); // Changed to 2D2D2D
        container.setLayout(new GridLayout(1, 2));

        JPanel leftPanel = new JPanel();
        leftPanel.setBackground(Color.decode("#EEEEEE"));
        leftPanel.setForeground(Color.decode("#2D2D2D")); // Changed to 2D2D2D
        leftPanel.setLayout(new GridLayout(3, 1)); // Set layout for three lines

        // Adding transfer handler to make it a drag and drop box
        leftPanel.setTransferHandler(new TransferHandler("text"));

        leftPanel.setDropTarget(new DropTarget() {
            public synchronized void drop(DropTargetDropEvent evt) {
                try {
                    evt.acceptDrop(DnDConstants.ACTION_COPY);
                    droppedFiles.clear();
                    List<File> droppedFiles = (List<File>) evt.getTransferable()
                            .getTransferData(DataFlavor.javaFileListFlavor);
                    for (File file : droppedFiles) {
                        // Add the file names to the global array
                        MainClass.this.droppedFiles.add(file.getPath());
                        //JOptionPane.showMessageDialog(null, "File Dropped: " + file); // Print the name of each file to the messagebox
                    }
                    selectedFilesLabel.setText("Selected Files: " + droppedFiles.size());
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        });

        // Add the inscription in three lines
        JLabel line1 = new JLabel("Drag & Drop Files Here");
        JLabel line2 = new JLabel("or");
        JLabel line3 = new JLabel("Click to Select");

        // Set alignment for the lines
        line1.setHorizontalAlignment(SwingConstants.CENTER);
        line2.setHorizontalAlignment(SwingConstants.CENTER);
        line3.setHorizontalAlignment(SwingConstants.CENTER);

        // Set font for the lines
        line1.setFont(segoeUiSemibold);
        line2.setFont(segoeUiSemibold);
        line3.setFont(segoeUiSemibold);

        // Add the lines to the left panel
        leftPanel.add(line1);
        leftPanel.add(line2);
        leftPanel.add(line3);

        leftPanel.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setMultiSelectionEnabled(true);
                fileChooser.showOpenDialog(null);
                droppedFiles.clear();
                File[] selectedFiles = fileChooser.getSelectedFiles();
                for (File file : selectedFiles) {
                	MainClass.this.droppedFiles.add(file.getPath());
                }
                selectedFilesLabel.setText("Selected Files: " + droppedFiles.size());
            }
        });

		container.add(leftPanel);

		JPanel rightPanel = new JPanel();
		rightPanel.setBackground(Color.decode("#2D2D2D"));
		rightPanel.setForeground(Color.decode("#EEEEEE"));
		rightPanel.setLayout(new GridLayout(3, 1));

		selectedFilesLabel = new JLabel("Selected Files: 0");
		selectedFilesLabel.setFont(segoeUiSemibold);
		selectedFilesLabel.setForeground(Color.decode("#EEEEEE"));
		selectedFilesLabel.setHorizontalAlignment(SwingConstants.CENTER);

		JPanel textFieldPanel = new JPanel(new BorderLayout());
		JLabel keyLabel = new JLabel("     Key:  ");
		keyLabel.setFont(segoeUiSemibold);
		keyLabel.setForeground(Color.decode("#EEEEEE"));
		keyLabel.setBackground(Color.decode("#2D2D2D"));
		textFieldPanel.add(keyLabel, BorderLayout.WEST);
		textFieldPanel.setForeground(Color.decode("#EEEEEE"));
		textFieldPanel.setBackground(Color.decode("#2D2D2D"));

		textField = new JPasswordField();
		textField.setFont(segoeUiSemibold);
		textField.setForeground(Color.decode("#EEEEEE"));
		textField.setBackground(Color.decode("#2D2D2D"));
		textField.setBorder(BorderFactory.createLineBorder(Color.decode("#2D2D2D")));
		textField.setCaretColor(Color.decode("#BBBBBB"));
		textField.setEchoChar('#');
		textFieldPanel.add(textField, BorderLayout.CENTER);

		JPanel buttonPanel = new JPanel();
		buttonPanel.setLayout(new GridLayout(1, 2));

		JButton encryptButton = new JButton("Encrypt");
		encryptButton.setFont(segoeUiSemibold);
		encryptButton.setBackground(Color.decode("#2D2D2D"));
		encryptButton.setForeground(Color.decode("#10A95B"));
		encryptButton.setBorder(BorderFactory.createLineBorder(Color.decode("#2D2D2D")));
		
		encryptButton.addActionListener((ActionListener) new ActionListener() {
            public void actionPerformed(ActionEvent e) {
            	try {
					derive_key_from_textfield();
				} catch (NoSuchAlgorithmException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
            	try {
					encryptFiles();
				} catch (Exception e1) {
					JOptionPane.showMessageDialog(null, e1, "Error", JOptionPane.ERROR_MESSAGE);
				}
            }
        });

		JButton decryptButton = new JButton("Decrypt");
		decryptButton.setFont(segoeUiSemibold);
		decryptButton.setBackground(Color.decode("#2D2D2D"));
		decryptButton.setForeground(Color.decode("#10A95B"));
		decryptButton.setBorder(BorderFactory.createLineBorder(Color.decode("#2D2D2D")));
		
		decryptButton.addActionListener((ActionListener) new ActionListener() {
            public void actionPerformed(ActionEvent e) {
            	try {
					derive_key_from_textfield();
				} catch (NoSuchAlgorithmException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
            	try {
					decryptFiles();
				} catch (Exception e1) {
					JOptionPane.showMessageDialog(null, e1, "Error", JOptionPane.ERROR_MESSAGE);
				}
            }
        });

		buttonPanel.add(encryptButton);
		buttonPanel.add(decryptButton);

		rightPanel.add(selectedFilesLabel);
		rightPanel.add(textFieldPanel);
		rightPanel.add(buttonPanel);

	    container.add(rightPanel);

	    background.add(container);

	    setPreferredSize(new Dimension(800, 346));
	    setMinimumSize(new Dimension(800, 346));
	    pack();
	    setLocationRelativeTo(null);
	    setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    }

    public static void main(String[] args) {
	    SwingUtilities.invokeLater(() -> {
		    MainClass form = new MainClass();
		    form.setVisible(true);
	    });
    }
    
    public static void about_form() {
        JFrame aboutForm = new JFrame("About AES-256 CBC File Encrypter");
        aboutForm.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        aboutForm.setSize(540, 460);
        aboutForm.getContentPane().setBackground(Color.decode("#7B08A5"));
        aboutForm.setLayout(new BoxLayout(aboutForm.getContentPane(), BoxLayout.Y_AXIS));

        JLabel label1 = createLabel("AES-256 CBC File Encrypter is an open-source software distributed under the MIT License.");
        JLabel label2 = createLabel("You are free to modify and distribute copies of the AES-256 CBC File Encrypter.");
        JLabel label3 = createLabel("You can use the AES-256 CBC File Encrypter in commercial applications.");
        JLabel label4 = createLabel("AES-256 CBC File Encrypter app and its source code can be found on:");
        JLabel label5 = createLabel("SourceForge");
        JLabel label6 = createLabel("GitHub");
        JLabel label7 = createLabel("Copyright " + "\u00a9" + " 2024 Maxim Bortnikov");

        addEmptySpace(aboutForm, 11); // Change the empty space to 11

        JTextField textField1 = createUneditableTextField();
        textField1.setText("sourceforge.net/projects/aes-256-cbc-file-encrypter/");
        JTextField textField2 = createUneditableTextField();
        textField1.setText("github.com/Northstrix/AES-256_CBC_File_Encrypter");

        addEmptySpace(aboutForm, 11); // Change the empty space to 11

        JButton okButton = new JButton("OK");

        // Set alignment for labels and add components to the form
        label1.setAlignmentX(Component.CENTER_ALIGNMENT);
        aboutForm.add(label1);
        label2.setAlignmentX(Component.CENTER_ALIGNMENT);
        aboutForm.add(label2);
        label3.setAlignmentX(Component.CENTER_ALIGNMENT);
        aboutForm.add(label3);
        addEmptySpace(aboutForm, 11); // Change the empty space to 11
        label4.setAlignmentX(Component.CENTER_ALIGNMENT);
        aboutForm.add(label4);
        addEmptySpace(aboutForm, 11); // Change the empty space to 11
        label5.setAlignmentX(Component.CENTER_ALIGNMENT);
        aboutForm.add(label5);
        textField1.setAlignmentX(Component.CENTER_ALIGNMENT);
        aboutForm.add(textField1);
        addEmptySpace(aboutForm, 11); // Change the empty space to 11
        label6.setAlignmentX(Component.CENTER_ALIGNMENT);
        aboutForm.add(label6);
        textField2.setAlignmentX(Component.CENTER_ALIGNMENT);
        aboutForm.add(textField2);
        addEmptySpace(aboutForm, 11); // Change the empty space to 11
        label7.setAlignmentX(Component.CENTER_ALIGNMENT);
        aboutForm.add(label7);
        addEmptySpace(aboutForm, 11); // Change the empty space to 11
        okButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        aboutForm.add(okButton);
        okButton.addActionListener((ActionListener) new ActionListener() {
            public void actionPerformed(ActionEvent e) {
            	aboutForm.dispose();
            }
        });
        aboutForm.setLocationRelativeTo(null);
        aboutForm.setVisible(true);
    }

    public static JLabel createLabel(String text) {
        JLabel label = new JLabel(text);
        label.setForeground(Color.decode("#EEEEEE"));
        label.setFont(new Font("Segoe UI", Font.BOLD, 12));
        label.setBorder(BorderFactory.createEmptyBorder(0, 0, 20, 0));
        return label;
    }

    public static JTextField createUneditableTextField() {
        JTextField textField = new JTextField(100);
        textField.setEditable(false);
        textField.setBackground(Color.decode("#7B08A5"));
        textField.setForeground(Color.decode("#EEEEEE"));
        textField.setFont(new Font("Segoe UI", Font.BOLD, 12));
        return textField;
    }
    
    public static void addEmptySpace(Container container, int height) {
        container.add(Box.createRigidArea(new Dimension(0, height)));
    }
}