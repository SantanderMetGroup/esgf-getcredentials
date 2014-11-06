package es.unican.meteo.esgf.myproxyclient;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.HeadlessException;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;

import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

public class CredentialsProviderGUI extends JFrame {

	private static String[] nodes = { "esgf-index1.ceda.ac.uk",
			"pcmdi9.llnl.gov", "esgf-node.ipsl.fr", "esgf-data.dkrz.de",
			"data.meteo.unican.es", "esgdata.gfdl.noaa.gov", "dev.esg.anl.gov",
			"esg.bnu.edu.cn", "adm07.cmcc.it", "euclipse1.dkrz.de",
			"esgf.nccs.nasa.gov", "esg-datanode.jpl.nasa.gov",
			"esg2.nci.org.au", "esg01.nersc.gov", "esg.ccs.ornl.gov" };
	private CredentialsProvider credentialsProvider;
	private JButton btRetrieve;
	private JTextArea txaMessages;
	private JComboBox idpCombo;
	private JTextField userField;
	private JPasswordField passField;

	public CredentialsProviderGUI(
			CredentialsProvider credentialsProvider)
			throws HeadlessException {
		super("ESGF MyProxy service client");

		this.credentialsProvider = credentialsProvider;
		configureBtRetrieveButton();

		JPanel idPanel = generateIdPanel();
		JPanel optionPanel = generateWriteOptionPanel();
		JPanel messagePanel = generateMessagePanel();

		JPanel auxPanel = new JPanel(new BorderLayout());
		auxPanel.add(idPanel, BorderLayout.NORTH);
		auxPanel.add(optionPanel, BorderLayout.SOUTH);

		JPanel mainPanel = new JPanel(new BorderLayout());
		mainPanel.add(auxPanel, BorderLayout.CENTER);
		mainPanel.add(btRetrieve, BorderLayout.SOUTH);

		setLayout(new BorderLayout());
		add(mainPanel, BorderLayout.CENTER);
		add(messagePanel, BorderLayout.SOUTH);

		pack();
		setVisible(true);
	}

	/**
	 * Configure the button "Retrieve credentials"
	 */
	private void configureBtRetrieveButton() {
		btRetrieve = new JButton("Retrieve credentials");
		btRetrieve.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent paramActionEvent) {
				try {
					String user = userField.getText().trim();
					char[] password = passField.getPassword();
					if (user != null && password != null && !user.equals("")
							&& password.length > 0) {

						if (idpCombo.getSelectedItem().equals(
								"<< Custom OpenID URL >>")) {
							credentialsProvider.setOpenID(user, password);
						} else {
							String completeOpenID = "https://"
									+ idpCombo.getSelectedItem()
									+ "/esgf-idp/openid/" + user;
							credentialsProvider.setOpenID(completeOpenID,
									password);
						}

						// retrieve credentials
						System.out.println("Using "
								+ credentialsProvider.getMyProxyLib()
								+ " lib...");
						credentialsProvider.retrieveCredentials();
						addMessage("Success!");

					} else {
						if (user == null || user.equals("")) {
							addMessage("The openID has not been configured.");
						} else {
							addMessage("The password has not been entered.");
						}
					}

				} catch (Exception e) {
					StringWriter sw = new StringWriter();
					PrintWriter pw = new PrintWriter(sw);
					e.printStackTrace(pw);
					addMessage(e.getMessage() + " " + sw.toString());
				}

			}

		});
	}

	/**
	 * Configure and generate option panel
	 * 
	 * @return
	 */
	private JPanel generateWriteOptionPanel() {

		// Init atributtes
		JPanel optPanel = new JPanel(new GridLayout(6, 1));
		final JCheckBox chkPem = new JCheckBox("credentials.pem");
		final JCheckBox chkJKS = new JCheckBox("keystore (JKS type)");
		final JCheckBox chkJCEKS = new JCheckBox("keystore (JCEKS type)");
		final JCheckBox chkTruststore = new JCheckBox("esgf-truststore");
		final JCheckBox chkCerts = new JCheckBox("certificates");
		final JCheckBox chkCacerts = new JCheckBox("ca-certs.pem");
		chkCacerts.setEnabled(false);

		// Checkboxes listener
		ItemListener writeOptionsListener = new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent paramItemEvent) {
				JCheckBox source = (JCheckBox) paramItemEvent
						.getItemSelectable();
				if (source == chkPem) {
					credentialsProvider.setWritePem(source.isSelected());
				} else if (source == chkJKS) {
					credentialsProvider
							.setWriteJKSKeystore(source.isSelected());
				} else if (source == chkJCEKS) {
					credentialsProvider.setWriteJCEKSKeystore(source
							.isSelected());
				} else if (source == chkTruststore) {
					credentialsProvider.setWriteTruststore(source.isSelected());
				} else if (source == chkCerts) {
					credentialsProvider.setWriteTrustRootsCerts(source
							.isSelected());
					// cacerts only can be generated if certificates are
					// retrieved
					if (source.isSelected()) {
						chkCacerts.setEnabled(true);
					} else {
						chkCacerts.setEnabled(false);
						chkCacerts.setSelected(false);
					}
				} else if (source == chkCacerts) {
					credentialsProvider.setWriteCaCertsPem(source.isSelected());
				}
			}
		};

		// configure check boxes
		chkPem.addItemListener(writeOptionsListener);
		chkPem.setSelected(true);
		chkJKS.addItemListener(writeOptionsListener);
		chkJKS.setSelected(false);
		chkJCEKS.addItemListener(writeOptionsListener);
		chkJCEKS.setSelected(false);
		chkTruststore.addItemListener(writeOptionsListener);
		chkTruststore.setSelected(true);
		chkCerts.addItemListener(writeOptionsListener);
		chkCerts.setSelected(true);
		chkCacerts.addItemListener(writeOptionsListener);
		chkCacerts.setSelected(false);

		// configure optPanel
		optPanel.add(chkPem);
		optPanel.add(chkJKS);
		optPanel.add(chkJCEKS);
		optPanel.add(chkTruststore);
		optPanel.add(chkCerts);
		optPanel.add(chkCacerts);

		optPanel.setBorder(BorderFactory.createTitledBorder("Generate:"));

		return optPanel;
	}

	private JPanel generateMessagePanel() {
		JPanel messagePanel = new JPanel(new BorderLayout());
		txaMessages = new JTextArea(" ");
		txaMessages.setWrapStyleWord(true);
		txaMessages.setColumns(20);
		txaMessages.setLineWrap(true);
		txaMessages.setRows(7);
		txaMessages.setWrapStyleWord(true);
		txaMessages.setEditable(false);
		messagePanel.add(new JScrollPane(txaMessages), BorderLayout.CENTER);
		return messagePanel;
	}

	private void addMessage(String message) {
		txaMessages.setText(message);
		txaMessages.moveCaretPosition(0);
	}

	/**
	 * Generate id panel
	 * 
	 * @return
	 */
	private JPanel generateIdPanel() {
		JPanel idPanel = new JPanel(new BorderLayout());
		final JPanel introPanel = new JPanel(new GridBagLayout());

		// providers
		JLabel providerLabel = new JLabel("Id Provider:");
		idpCombo = new JComboBox(nodes);
		idpCombo.addItem("<< Custom OpenID URL >>");

		// user & password
		String userStr = "https://" + idpCombo.getSelectedItem()
				+ "/esgf-idp/openid/";
		final JLabel userLabel = new JLabel(userStr);
		userField = new JTextField(20);
		JLabel passLabel = new JLabel("password:");
		passField = new JPasswordField(20);

		// Build the intro panel
		GridBagConstraints constraints = new GridBagConstraints();

		// providers
		constraints.fill = GridBagConstraints.HORIZONTAL;
		constraints.gridx = 0;
		constraints.gridy = 0;
		constraints.gridwidth = 1; // reset width
		constraints.anchor = GridBagConstraints.EAST;
		constraints.fill = GridBagConstraints.NONE;
		introPanel.add(providerLabel, constraints);
		constraints.gridx = 1;
		constraints.gridy = 0;
		constraints.anchor = GridBagConstraints.CENTER;// reset
		constraints.fill = GridBagConstraints.HORIZONTAL;// reset
		introPanel.add(idpCombo, constraints);

		// user & password
		constraints.gridx = 0;
		constraints.gridy = 1;
		introPanel.add(userLabel, constraints);
		constraints.gridx = 1;
		constraints.gridy = 1;
		introPanel.add(userField, constraints);
		constraints.gridx = 0;
		constraints.gridy = 2;
		constraints.anchor = GridBagConstraints.EAST;
		constraints.fill = GridBagConstraints.NONE;
		introPanel.add(passLabel, constraints);
		constraints.gridx = 1;
		constraints.gridy = 2;
		constraints.anchor = GridBagConstraints.CENTER;// reset
		constraints.fill = GridBagConstraints.HORIZONTAL;// reset
		introPanel.add(passField, constraints);

		// listener of idpComboBox
		idpCombo.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				if (idpCombo.getSelectedItem()
						.equals("<< Custom OpenID URL >>")) {
					userField.setColumns(35);
					userField
							.setText("https://[IdPNodeName]/esgf-idp/openid/[userName]");

					// change position in intro panel
					GridBagConstraints constraints = new GridBagConstraints();
					constraints.fill = GridBagConstraints.HORIZONTAL;
					constraints.gridx = 0;
					constraints.gridy = 1;
					constraints.gridwidth = 2;
					introPanel.add(userField, constraints);

					validate();
					repaint();
				} else {
					String userStr = "https://" + idpCombo.getSelectedItem()
							+ "/esgf-idp/openid/";
					userLabel.setText(userStr);
					userField.setColumns(20);
					userField.setText("");

					// change position in intro panel
					GridBagConstraints constraints = new GridBagConstraints();
					constraints.fill = GridBagConstraints.HORIZONTAL;
					constraints.gridx = 0;
					constraints.gridy = 1;
					constraints.gridwidth = 1;
					introPanel.add(userLabel, constraints);
					constraints.gridx = 1;
					constraints.gridy = 1;
					introPanel.add(userField, constraints);

					validate();
					repaint();
				}
			}
		});

		// Options of folder in idpPanel
		JPanel idFolOptsPanel = new JPanel(new GridLayout(2, 2));
		final JRadioButton rbEsgFol = new JRadioButton("Default folder (.esg)");
		rbEsgFol.setSelected(true);
		final JRadioButton rbAnotherFol = new JRadioButton("Another folder");
		final ButtonGroup folGroup = new ButtonGroup(); // radio button group
		folGroup.add(rbEsgFol);
		folGroup.add(rbAnotherFol);
		final JCheckBox chkBootstrap = new JCheckBox("bootstrap certificates");
		chkBootstrap.setSelected(false);
		chkBootstrap.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				JCheckBox source = (JCheckBox) e.getItemSelectable();
				credentialsProvider.setBootstrap(source.isSelected());
			}
		});

		final JButton btChangeCredFol = new JButton("Change esg folder");
		btChangeCredFol.setEnabled(false);
		final JPanel btPanelAux = new JPanel(new FlowLayout(FlowLayout.LEFT));
		btPanelAux.add(btChangeCredFol);
		idFolOptsPanel.add(rbEsgFol);
		idFolOptsPanel.add(new JLabel(" "));
		idFolOptsPanel.add(rbAnotherFol);
		idFolOptsPanel.add(btPanelAux);
		idFolOptsPanel.setBorder(BorderFactory
				.createTitledBorder("Select folder:"));

		// Options of MyProxy Lib in idpPanel
		JPanel idLibOptsPanel = new JPanel(new GridLayout(4, 1));
		final JRadioButton rbMyProxyLogon = new JRadioButton(
				"use MyProxyLogon lib (v-1.0)");
		rbMyProxyLogon.setSelected(true);
		final JRadioButton rbMyProxy206 = new JRadioButton(
				"use MyProxy lib (v-2.0.6)");
		final ButtonGroup myProxyGroup = new ButtonGroup(); // radio button
															// group
		myProxyGroup.add(rbMyProxyLogon);
		myProxyGroup.add(rbMyProxy206);
		idLibOptsPanel.add(rbMyProxyLogon);
		idLibOptsPanel.add(rbMyProxy206);
		idLibOptsPanel.add(new JLabel(" "));
		idLibOptsPanel.add(chkBootstrap);
		idLibOptsPanel.setBorder(BorderFactory
				.createTitledBorder("Select lib:"));

		// button listener
		btChangeCredFol.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent paramActionEvent) {
				JFileChooser fileChooser = new JFileChooser(System
						.getProperty("user.dir"));
				fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
				int returnVal = fileChooser.showSaveDialog(null);

				if (returnVal == JFileChooser.APPROVE_OPTION) {
					File file = fileChooser.getSelectedFile();
					String path = file.getAbsolutePath();
					rbAnotherFol.setText("Another folder: " + path);
					credentialsProvider.setCredentialsDirectory(path);
				}

			}
		});

		// opts listener
		ActionListener idOptionsListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent paramActionEvent) {
				JRadioButton source = (JRadioButton) paramActionEvent
						.getSource();
				if (source == rbEsgFol) {
					credentialsProvider.resetCredentialsDirectory();
					btChangeCredFol.setEnabled(false);
					rbAnotherFol.setText("Another folder");
				} else if (source == rbAnotherFol) {
					btChangeCredFol.setEnabled(true);
				} else if (source == rbMyProxyLogon) {
					credentialsProvider
							.setMyProxyLib(CredentialsProvider.Lib.MYPROXYLOGON);
					chkBootstrap.setSelected(false);
					chkBootstrap.setEnabled(true);
				} else if (source == rbMyProxy206) {
					credentialsProvider // always bootstrap
							.setMyProxyLib(CredentialsProvider.Lib.MYPROXYV206);
					chkBootstrap.setSelected(true);
					chkBootstrap.setEnabled(false);
				}
			}
		};

		// addListeners to radio buttons
		rbEsgFol.addActionListener(idOptionsListener);
		rbAnotherFol.addActionListener(idOptionsListener);
		rbMyProxyLogon.addActionListener(idOptionsListener);
		rbMyProxy206.addActionListener(idOptionsListener);
		// panel of idp options
		JPanel optsPanel = new JPanel(new BorderLayout());
		optsPanel.add(idFolOptsPanel, BorderLayout.CENTER);
		optsPanel.add(idLibOptsPanel, BorderLayout.EAST);

		idPanel.add(introPanel, BorderLayout.CENTER);
		idPanel.add(optsPanel, BorderLayout.SOUTH);
		return idPanel;
	}

	public static void main(String args[]) {
		CredentialsProvider credentialsProvider = CredentialsProvider
				.getInstance();
		CredentialsProviderGUI ui = new CredentialsProviderGUI(
				credentialsProvider);
	}
}
