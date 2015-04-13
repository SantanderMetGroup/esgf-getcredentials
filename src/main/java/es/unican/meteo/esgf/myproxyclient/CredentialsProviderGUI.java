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
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

public class CredentialsProviderGUI extends JFrame {

    private String[] nodes;
    private CredentialsProvider credentialsProvider;
    private JButton btRetrieve;
    private JTextArea txaMessages;
    private JComboBox idpCombo;
    private JTextField userField;
    private JPasswordField passField;
    private ImageIcon loadingIcon;
    private JPanel messagePanel;

    public CredentialsProviderGUI(CredentialsProvider credentialsProvider,
            String[] nodes) throws HeadlessException {
        super("ESGF Credentials Provider");

        this.credentialsProvider = credentialsProvider;
        this.loadingIcon = new ImageIcon(getClass().getClassLoader()
                .getResource("ajax-loader.gif"));
        this.nodes = nodes;

        configureBtRetrieveButton();

        JPanel idPanel = generateIdPanel();
        JPanel optionPanel = generateWriteOptionPanel();
        messagePanel = generateMessagePanel();

        JPanel auxPanel = new JPanel(new BorderLayout());
        auxPanel.add(idPanel, BorderLayout.NORTH);
        auxPanel.add(optionPanel, BorderLayout.SOUTH);

        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(auxPanel, BorderLayout.CENTER);
        mainPanel.add(btRetrieve, BorderLayout.SOUTH);

        setLayout(new BorderLayout());
        add(mainPanel, BorderLayout.CENTER);
        add(messagePanel, BorderLayout.SOUTH);

        // add(new JLabel("loading... ", loading, JLabel.CENTER));

        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
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

                // If any file wasn't selected to be generated, notify it
                if (!credentialsProvider.isWriteCaCertsPem()
                        && !credentialsProvider.isWriteJCEKSKeystore()
                        && !credentialsProvider.isWriteJKSKeystore()
                        && !credentialsProvider.isWritePem()
                        && !credentialsProvider.isWriteTrustRootsCerts()
                        && !credentialsProvider.isWriteTruststore()) {
                    JOptionPane
                            .showMessageDialog(CredentialsProviderGUI.this,
                                    "There is no file selected in \"Generate\" section");

                } else {
                    try {

                        String user = userField.getText().trim();
                        char[] password = passField.getPassword();
                        if (user != null && password != null
                                && !user.equals("") && password.length > 0) {

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

                            final JDialog busyDialog = new JDialog(
                                    CredentialsProviderGUI.this);
                            JLabel lbWait = new JLabel("retrieving... ",
                                    CredentialsProviderGUI.this.loadingIcon,
                                    JLabel.CENTER);
                            busyDialog.add(lbWait);
                            busyDialog
                                    .setLocationRelativeTo(CredentialsProviderGUI.this);
                            busyDialog.setUndecorated(true);
                            busyDialog.pack();
                            busyDialog.setAlwaysOnTop(true);
                            busyDialog.setVisible(false);

                            Thread thread = new Thread(new Runnable() {
                                @Override
                                public void run() {
                                    busyDialog.setVisible(true);
                                    CredentialsProviderGUI.this.btRetrieve
                                            .setEnabled(false);
                                    try {
                                        CredentialsProviderGUI.this.credentialsProvider
                                                .retrieveCredentials();
                                        printMessageSuccess();
                                    } catch (Exception e) {
                                        if (e.getMessage() != null
                                                && (e.getMessage()
                                                        .equals(CredentialsProviderGUI.this.credentialsProvider
                                                                .getOpenID()))) {
                                            StackTraceElement[] stacktrace = e
                                                    .getStackTrace();
                                            if (stacktrace.length > 0) {
                                                if (stacktrace[0]
                                                        .getFileName()
                                                        .equals("HttpURLConnection.java")) {
                                                    StringWriter sw = new StringWriter();
                                                    PrintWriter pw = new PrintWriter(
                                                            sw);
                                                    e.printStackTrace(pw);
                                                    addMessage("Exception in HttpURLConnection. Incorrect OpenID URL. \n"
                                                            + e.getMessage()
                                                            + " "
                                                            + sw.toString());
                                                }
                                            }
                                        } else {
                                            StringWriter sw = new StringWriter();
                                            PrintWriter pw = new PrintWriter(sw);
                                            e.printStackTrace(pw);
                                            addMessage(e.getMessage() + " "
                                                    + sw.toString());
                                        }
                                    }
                                    busyDialog.dispose();
                                    CredentialsProviderGUI.this.btRetrieve
                                            .setEnabled(true);
                                    validate();
                                    repaint();
                                }
                            });

                            thread.start();

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
            }

        });
    }

    private void printMessageSuccess() {
        String messageStr = "Success!\n";
        messageStr = messageStr + "The follow files have been written in "
                + credentialsProvider.getCredentialsDirectory() + "\n";

        if (credentialsProvider.isWritePem()) {
            messageStr = messageStr + "- User certificate and private"
                    + " key in pem format" + "\n";
        }
        if (credentialsProvider.isWriteCaCertsPem()) {
            messageStr = messageStr + "- Trust CA certificates in pem format"
                    + "\n";
        }
        if (credentialsProvider.isWriteTruststore()) {
            messageStr = messageStr
                    + "- Trust CA certificates in JKS keystore format" + "\n";
        }
        if (credentialsProvider.isWriteTrustRootsCerts()) {
            messageStr = messageStr + "- Trust CA certificates in a folder"
                    + "\n";
        }
        if (credentialsProvider.isWriteJKSKeystore()) {
            messageStr = messageStr
                    + "- JKS keystore file. This keystore contains certificate,"
                    + " certificate chain and private key of user" + "\n";
        }
        if (credentialsProvider.isWriteJCEKSKeystore()) {
            messageStr = messageStr
                    + "- JCEKS keystore file. This keystore contains certificate,"
                    + " certificate chain and private key of user" + "\n";
        }
        addMessage(messageStr);

    }

    /**
     * Configure and generate option panel
     * 
     * @return
     */
    private JPanel generateWriteOptionPanel() {

        // Main panel
        JPanel mainOptPanel = new JPanel(new BorderLayout());
        mainOptPanel.setBorder(BorderFactory.createTitledBorder("Generate:"));

        // keystore password options
        final JPanel keypassOptPanel = new JPanel(new GridLayout(2, 1));
        keypassOptPanel.setVisible(false);

        // Write options checkboxes
        JPanel writeOptPanel = new JPanel(new GridLayout(6, 1));
        final JCheckBox chkPem = new JCheckBox("credentials.pem");
        chkPem.setToolTipText("User certificate and private key in pem format");
        final JCheckBox chkJKS = new JCheckBox("keystore (JKS type)");
        chkJKS.setToolTipText("JKS keystore file. This keystore contains certificate,"
                + " certificate chain and private key of user");
        final JCheckBox chkJCEKS = new JCheckBox("keystore (JCEKS type)");
        chkJCEKS.setToolTipText("JCEKS keystore file. This keystore contains certificate,"
                + " certificate chain and private key of user");
        final JCheckBox chkTruststore = new JCheckBox("esg-truststore.ts");
        chkTruststore
                .setToolTipText("Trust CA certificates in JKS keystore format");
        final JCheckBox chkCerts = new JCheckBox("certificates");
        chkCerts.setToolTipText("Trust CA certificates in a folder");
        final JCheckBox chkCacerts = new JCheckBox("ca-certificates.pem");
        chkCacerts.setToolTipText(" Trust CA certificates in pem format");

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
                } else if (source == chkCacerts) {
                    credentialsProvider.setWriteCaCertsPem(source.isSelected());
                }

                // At the end if chkJKS OR chkJCEKS are selected
                // put on keystore password options. Else if chkJKS AND chkJCEKS
                // aren't selected put off keystore password options.

                if (chkJKS.isSelected() | chkJCEKS.isSelected()) {
                    keypassOptPanel.setVisible(true);
                } else if (!chkJKS.isSelected() && !chkJCEKS.isSelected()) {
                    keypassOptPanel.setVisible(false);
                }
            }
        };

        // configure check boxes
        chkPem.addItemListener(writeOptionsListener);
        chkPem.setSelected(false);
        chkJKS.addItemListener(writeOptionsListener);
        chkJKS.setSelected(false);
        chkJCEKS.addItemListener(writeOptionsListener);
        chkJCEKS.setSelected(false);
        chkTruststore.addItemListener(writeOptionsListener);
        chkTruststore.setSelected(false);
        chkCerts.addItemListener(writeOptionsListener);
        chkCerts.setSelected(false);
        chkCacerts.addItemListener(writeOptionsListener);
        chkCacerts.setSelected(false);

        // configure optPanel
        writeOptPanel.add(chkPem);
        writeOptPanel.add(chkJKS);
        writeOptPanel.add(chkJCEKS);
        writeOptPanel.add(chkTruststore);
        writeOptPanel.add(chkCerts);
        writeOptPanel.add(chkCacerts);

        // Profiles combo box
        JPanel profilesPanel = new JPanel(new FlowLayout());
        String[] profiles = { "----", "ESGF WGET Script (OpenSSL)",
                "ESGF WGET Script (GNU TLS)", "Aria2", "ToolsUI NetCDF" };
        final JComboBox cBoxProfiles = new JComboBox(profiles);
        cBoxProfiles.setBorder(BorderFactory
                .createTitledBorder("Selection profiles:"));
        cBoxProfiles.setToolTipText("Case use profiles to automatic"
                + " file selection");
        // listener of idpComboBox
        cBoxProfiles.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent arg0) {
                if (cBoxProfiles.getSelectedItem().equals(
                        "ESGF WGET Script (OpenSSL)")) {
                    chkPem.setSelected(true);
                    chkJKS.setSelected(false);
                    chkJCEKS.setSelected(false);
                    chkTruststore.setSelected(true);
                    chkCerts.setSelected(true);
                    chkCacerts.setSelected(false);
                } else if (cBoxProfiles.getSelectedItem().equals(
                        "ESGF WGET Script (GNU TLS)")) {
                    chkPem.setSelected(true);
                    chkJKS.setSelected(false);
                    chkJCEKS.setSelected(false);
                    chkTruststore.setSelected(true);
                    chkCerts.setSelected(false);
                    chkCacerts.setSelected(true);
                } else if (cBoxProfiles.getSelectedItem().equals("Aria2")) {
                    chkPem.setSelected(true);
                    chkJKS.setSelected(false);
                    chkJCEKS.setSelected(false);
                    chkTruststore.setSelected(false);
                    chkCerts.setSelected(false);
                    chkCacerts.setSelected(true);
                } else if (cBoxProfiles.getSelectedItem().equals(
                        "ToolsUI NetCDF")) {
                    chkPem.setSelected(false);
                    chkJKS.setSelected(true);
                    chkJCEKS.setSelected(false);
                    chkTruststore.setSelected(true);
                    chkCerts.setSelected(false);
                    chkCacerts.setSelected(false);
                } else if (cBoxProfiles.getSelectedItem().equals("----")) {
                    chkPem.setSelected(false);
                    chkJKS.setSelected(false);
                    chkJCEKS.setSelected(false);
                    chkTruststore.setSelected(false);
                    chkCerts.setSelected(false);
                    chkCacerts.setSelected(false);
                }
            }
        });
        profilesPanel.add(cBoxProfiles);

        // keystore password options
        keypassOptPanel
                .setToolTipText("Options to change the password of the keystores that will be generated");
        final JRadioButton rbDefaultPass = new JRadioButton("Default passw: changeit");
        rbDefaultPass.setSelected(true);
        final JRadioButton rbChangePass = new JRadioButton("Another passw: ");
        final ButtonGroup groupPass = new ButtonGroup(); // radio button group
        groupPass.add(rbDefaultPass);
        groupPass.add(rbChangePass);

        final JButton btChangePass = new JButton("Change password");
        btChangePass.setEnabled(false);
        // button listener
        btChangePass.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent paramActionEvent) {
                String passw = JOptionPane.showInputDialog("New password:");

                if (!passw.trim().equals("")) {
                    CredentialsProviderGUI.this.
                    credentialsProvider.setKeystorePass(passw);
                    rbChangePass.setText("Another folder: " + passw);
                }
            }
        });

        final JPanel auxDefaultPass = new JPanel(new FlowLayout(FlowLayout.LEFT));
        auxDefaultPass.add(rbDefaultPass);
        final JPanel auxAnotherPass = new JPanel(new FlowLayout(
                FlowLayout.LEFT));
        auxAnotherPass.add(rbChangePass);
        auxAnotherPass.add(btChangePass);

        keypassOptPanel.add(auxDefaultPass);
        keypassOptPanel.add(auxAnotherPass);
        keypassOptPanel.setBorder(BorderFactory
                .createTitledBorder("Keystore password options:"));

        // keystore password opts listener
        ActionListener optsListener = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent paramActionEvent) {
                JRadioButton source = (JRadioButton) paramActionEvent
                        .getSource();
                if (source == rbDefaultPass) {
                    credentialsProvider.setKeystorePass("changeit");
                    btChangePass.setEnabled(false);
                    rbChangePass.setText("Another passw: ");
                } else if (source == rbChangePass) {
                    btChangePass.setEnabled(true);
                }
            }
        };

        rbDefaultPass.addActionListener(optsListener);
        rbChangePass.addActionListener(optsListener);

        // east panel (Profiles combo box & keystore passw opts)
        JPanel eastPanel = new JPanel(new BorderLayout());
        eastPanel.add(profilesPanel, BorderLayout.NORTH);
        eastPanel.add(keypassOptPanel, BorderLayout.SOUTH);

        mainOptPanel.add(writeOptPanel, BorderLayout.WEST);
        mainOptPanel.add(eastPanel, BorderLayout.EAST);

        return mainOptPanel;
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

        boolean multLibraries = false;
        try {
            this.getClass().getClassLoader()
                    .loadClass("org.globus.myproxy.MyProxy");
            multLibraries = true;
        } catch (ClassNotFoundException e) {
        }

        JPanel idPanel = new JPanel(new BorderLayout());
        final JPanel introPanel = new JPanel(new GridBagLayout());

        // providers
        JLabel providerLabel = new JLabel("Id Provider:");
        providerLabel.setToolTipText("Identity provider of your account");
        idpCombo = new JComboBox(nodes);
        idpCombo.addItem("<< Custom OpenID URL >>");
        idpCombo.setToolTipText("Identity provider of your account");

        // user & password
        String userStr = "https://" + idpCombo.getSelectedItem()
                + "/esgf-idp/openid/";
        final JLabel userLabel = new JLabel(userStr);
        userLabel.setToolTipText("OpenID");
        userField = new JTextField(20);
        userField.setToolTipText("OpenID");
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
        JPanel idFolOptsPanel = new JPanel(new GridLayout(2, 1));
        idFolOptsPanel
                .setToolTipText("Options to select the folder where the files will be generated");
        final String defaultFolder = credentialsProvider
                .getCredentialsDirectory();
        final JRadioButton rbEsgFol = new JRadioButton("Default folder ("
                + defaultFolder + ")");
        rbEsgFol.setSelected(true);
        final JRadioButton rbAnotherFol = new JRadioButton("Another folder");
        final ButtonGroup folGroup = new ButtonGroup(); // radio button group
        folGroup.add(rbEsgFol);
        folGroup.add(rbAnotherFol);
        final JCheckBox chkBootstrap = new JCheckBox("bootstrap certificates");
        chkBootstrap.setSelected(false);
        chkBootstrap
                .setToolTipText("Bootstrapping certificates of myproxy service");
        chkBootstrap.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                JCheckBox source = (JCheckBox) e.getItemSelectable();
                credentialsProvider.setBootstrap(source.isSelected());
            }
        });

        final JButton btChangeCredFol = new JButton("Change esg folder");
        btChangeCredFol.setEnabled(false);
        final JPanel auxEsgFolder = new JPanel(new FlowLayout(FlowLayout.LEFT));
        auxEsgFolder.add(rbEsgFol);
        final JPanel auxAnotherFolder = new JPanel(new FlowLayout(
                FlowLayout.LEFT));
        auxAnotherFolder.add(rbAnotherFol);
        auxAnotherFolder.add(btChangeCredFol);
        idFolOptsPanel.add(auxEsgFolder);
        idFolOptsPanel.add(auxAnotherFolder);
        idFolOptsPanel.setBorder(BorderFactory
                .createTitledBorder("Select folder:"));

        // Options of MyProxy Lib in idpPanel
        JPanel idLibOptsPanel = new JPanel(new GridLayout(4, 1));
        idLibOptsPanel.setToolTipText("Configure myproxy client");
        if (multLibraries) {
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

            // opts listener
            ActionListener optsListener = new ActionListener() {
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
            rbEsgFol.addActionListener(optsListener);
            rbAnotherFol.addActionListener(optsListener);
            rbMyProxyLogon.addActionListener(optsListener);
            rbMyProxy206.addActionListener(optsListener);
        } else {
            idLibOptsPanel.add(chkBootstrap);
            idLibOptsPanel.setBorder(BorderFactory
                    .createTitledBorder("Bootstrapping:"));

            // opts listener
            ActionListener optsListener = new ActionListener() {
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
                    }
                }
            };

            rbEsgFol.addActionListener(optsListener);
            rbAnotherFol.addActionListener(optsListener);
        }

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

        // panel of idp options
        JPanel optsPanel = new JPanel(new BorderLayout());
        optsPanel.add(idFolOptsPanel, BorderLayout.CENTER);
        optsPanel.add(idLibOptsPanel, BorderLayout.EAST);

        idPanel.add(introPanel, BorderLayout.CENTER);
        idPanel.add(optsPanel, BorderLayout.SOUTH);
        return idPanel;
    }
}
