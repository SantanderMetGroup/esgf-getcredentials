package MyProxy;

import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Properties;
import java.util.logging.Logger;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

public class MyProxyLogonGUI extends JPanel implements ActionListener {
    private static final long serialVersionUID = 1L;
    static Logger logger = Logger.getLogger(MyProxyLogonGUI.class.getName());
    public static final String version = "1.1";
    protected MyProxyLogon myproxy = new MyProxyLogon();
    protected Properties properties;
    protected static final String PROPERTIES_PATH = "/.MyProxyLogon";
    protected JTextField usernameField;
    protected JLabel usernameFieldLabel;
    protected static final String usernameFieldString = "Username";
    protected static final String usernameFieldProperty = "Username";
    protected JPasswordField passwordField;
    protected JLabel passwordFieldLabel;
    protected static final String passwordFieldString = "Passphrase";
    protected static final String passwordFieldProperty = "Passphrase";
    protected static final String passwordInfoString = "Enter passphrase to logon.\n";
    protected JTextField crednameField;
    protected JLabel crednameFieldLabel;
    protected static final String crednameFieldString = "Credential Name";
    protected static final String crednameFieldProperty = "CredentialName";
    protected JTextField lifetimeField;
    protected JLabel lifetimeFieldLabel;
    protected static final String lifetimeFieldString = "Lifetime (hours)";
    protected static final String lifetimeFieldProperty = "Lifetime";
    protected JTextField hostnameField;
    protected JLabel hostnameFieldLabel;
    protected static final String hostnameFieldString = "Hostname";
    protected static final String hostnameFieldProperty = "Hostname";
    protected JTextField portField;
    protected JLabel portFieldLabel;
    protected static final String portFieldString = "Port";
    protected static final String portFieldProperty = "Port";
    protected JTextField outputField;
    protected JLabel outputFieldLabel;
    protected static final String outputFieldString = "Output";
    protected static final String outputFieldProperty = "Output";
    protected JCheckBox trustRootsCheckBox;
    protected static final String trustRootsProperty = "TrustRoots";
    protected static final String trustRootsPropertyYes = "yes";
    protected static final String trustRootsPropertyNo = "no";
    protected JButton button;
    protected static final String buttonFieldString = "Logon";
    protected JTextArea statusTextArea;
    protected JScrollPane statusScrollPane;

    public MyProxyLogonGUI() {
        loadProperties();
        GridBagLayout localGridBagLayout = new GridBagLayout();
        GridBagConstraints localGridBagConstraints = new GridBagConstraints();
        setLayout(localGridBagLayout);
        setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        this.usernameField = createField(
                "Username",
                this.properties.getProperty("Username",
                        this.myproxy.getUsername()));
        this.usernameFieldLabel = createLabel("Username", this.usernameField);
        this.usernameField.setToolTipText("Enter your MyProxy username.");
        this.passwordField = new JPasswordField(10);
        this.passwordField.setActionCommand("Passphrase");
        this.passwordField.addActionListener(this);
        this.passwordFieldLabel = createLabel("Passphrase", this.passwordField);
        this.passwordField.setToolTipText("Enter your MyProxy passphrase.");
        this.crednameField = createField(
                "Credential Name",
                this.properties.getProperty("CredentialName",
                        this.myproxy.getCredentialName()));
        this.crednameFieldLabel = createLabel("Credential Name",
                this.hostnameField);
        this.crednameField
                .setToolTipText("Optionally enter your MyProxy credential name.  Leave blank to use your default credential.");
        this.lifetimeField = createField(
                "Lifetime (hours)",
                this.properties.getProperty("Lifetime",
                        Integer.toString(this.myproxy.getLifetime() / 3600)));
        this.lifetimeFieldLabel = createLabel("Lifetime (hours)",
                this.lifetimeField);
        this.lifetimeField
                .setToolTipText("Enter the number of hours for your requested credentials to be valid.");
        this.hostnameField = createField("Hostname",
                this.properties.getProperty("Hostname", this.myproxy.getHost()));
        this.hostnameFieldLabel = createLabel("Hostname", this.hostnameField);
        this.hostnameField
                .setToolTipText("Enter the hostname of your MyProxy server (for example: myproxy.ncsa.uiuc.edu).");
        this.portField = createField(
                "Port",
                this.properties.getProperty("Port",
                        Integer.toString(this.myproxy.getPort())));
        this.portFieldLabel = createLabel("Port", this.portField);
        this.portField
                .setToolTipText("Enter the TCP port of your MyProxy server (usually 7512).");
        String str1 = MyProxyLogon.getTrustRootPath();
        String str2 = MyProxyLogon.getExistingTrustRootPath();
        this.trustRootsCheckBox = new JCheckBox("Write trust roots to " + str1
                + ".");
        String str3 = this.properties.getProperty("TrustRoots");
        if ((str3 != null) && (str3.equals("yes"))) {
            this.trustRootsCheckBox.setSelected(true);
        } else if ((str3 != null) && (str3.equals("no"))) {
            this.trustRootsCheckBox.setSelected(false);
        } else if ((str2 == null) || (str1.equals(str2))) {
            this.trustRootsCheckBox.setSelected(true);
        } else {
            this.trustRootsCheckBox.setSelected(false);
        }
        this.trustRootsCheckBox
                .setToolTipText("Check this box to download the latest CA certificates, certificate revocation lists, and CA signing policy files from MyProxy.");
        String str4;
        try {
            str4 = MyProxyLogon.getProxyLocation();
        } catch (Exception localException) {
            str4 = "";
        }
        this.outputField = createField("Output",
                this.properties.getProperty("Output", str4));
        this.outputFieldLabel = createLabel("Output", this.outputField);
        this.outputField
                .setToolTipText("Enter the path to store your credential from MyProxy.  Leave blank if you don't want to retrieve a credential.");
        JLabel[] arrayOfJLabel = { this.usernameFieldLabel,
                this.passwordFieldLabel, this.crednameFieldLabel,
                this.lifetimeFieldLabel, this.hostnameFieldLabel,
                this.portFieldLabel, this.outputFieldLabel };
        JTextField[] arrayOfJTextField = { this.usernameField,
                this.passwordField, this.crednameField, this.lifetimeField,
                this.hostnameField, this.portField, this.outputField };
        int i = arrayOfJLabel.length;
        localGridBagConstraints.anchor = 22;
        for (int j = 0; j < i; j++) {
            localGridBagConstraints.gridwidth = -1;
            localGridBagConstraints.fill = 0;
            localGridBagConstraints.weightx = 0.0D;
            add(arrayOfJLabel[j], localGridBagConstraints);
            localGridBagConstraints.gridwidth = 0;
            localGridBagConstraints.fill = 2;
            localGridBagConstraints.weightx = 1.0D;
            add(arrayOfJTextField[j], localGridBagConstraints);
        }
        this.button = new JButton("Logon");
        this.button.setActionCommand("Logon");
        this.button.addActionListener(this);
        this.button.setVerticalTextPosition(0);
        this.button.setHorizontalTextPosition(0);
        this.button.setToolTipText("Press this button to logon to MyProxy.");
        this.statusTextArea = new JTextArea(4, 10);
        this.statusTextArea.setEditable(false);
        this.statusTextArea.setLineWrap(true);
        this.statusTextArea.setWrapStyleWord(true);
        this.statusScrollPane = new JScrollPane(this.statusTextArea);
        this.statusTextArea.setText("Enter passphrase to logon.\n");
        this.statusTextArea
                .setToolTipText("This area contains status messages.");
        localGridBagConstraints.gridwidth = 0;
        localGridBagConstraints.fill = 2;
        localGridBagConstraints.weightx = 1.0D;
        add(this.trustRootsCheckBox, localGridBagConstraints);
        add(this.button, localGridBagConstraints);
        add(this.statusScrollPane, localGridBagConstraints);
    }

    @Override
    public void actionPerformed(ActionEvent paramActionEvent) {
        if ((verifyInput())
                && (("Passphrase".equals(paramActionEvent.getActionCommand())) || ("Logon"
                        .equals(paramActionEvent.getActionCommand())))) {
            logon();
        }
    }

    public static void main(String[] paramArrayOfString) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
            }
        });
    }

    protected void logon() {
        try {
            this.myproxy.setUsername(this.usernameField.getText());
            this.myproxy.setPassphrase(new String(this.passwordField
                    .getPassword()));
            if (this.crednameField.getText().length() > 0) {
                this.myproxy.setCredentialName(this.crednameField.getText());
            }
            this.myproxy.setLifetime(Integer.parseInt(this.lifetimeField
                    .getText()) * 3600);
            this.myproxy.setHost(this.hostnameField.getText());
            this.myproxy.setPort(Integer.parseInt(this.portField.getText()));
            this.myproxy
                    .requestTrustRoots(this.trustRootsCheckBox.isSelected());
            this.statusTextArea.setText("Connecting to "
                    + this.myproxy.getHost() + "...\n");
            this.myproxy.connect();
            this.statusTextArea.setText("Logging on...\n");
            this.myproxy.logon();
            if (this.outputField.getText().length() == 0) {
                this.statusTextArea.setText("Logon successful.\n");
            } else {
                this.statusTextArea.setText("Getting credentials...\n");
                this.myproxy.getCredentials();
                this.statusTextArea.setText("Writing credentials...\n");
                this.myproxy.saveCredentialsToFile(this.outputField.getText());
                this.statusTextArea.setText("Credentials written to "
                        + this.outputField.getText() + ".\n");
            }
            if ((this.trustRootsCheckBox.isSelected())
                    && (this.myproxy.writeTrustRoots())) {
                this.statusTextArea.append("Trust roots written to "
                        + MyProxyLogon.getTrustRootPath() + ".\n");
            }
            saveProperties();
            return;
        } catch (Exception localException2) {
            this.statusTextArea
                    .append("Error: " + localException2.getMessage());
        } finally {
            try {
                this.myproxy.disconnect();
            } catch (Exception localException4) {
            }
        }
    }

    protected void saveProperties() {
        try {
            FileOutputStream localFileOutputStream = new FileOutputStream(
                    System.getProperty("user.home") + "/.MyProxyLogon");
            this.properties.setProperty("Username",
                    this.usernameField.getText());
            this.properties.setProperty("CredentialName",
                    this.crednameField.getText());
            this.properties.setProperty("Lifetime",
                    this.lifetimeField.getText());
            this.properties.setProperty("Hostname",
                    this.hostnameField.getText());
            this.properties.setProperty("Port", this.portField.getText());
            this.properties.setProperty("Output", this.outputField.getText());
            this.properties.setProperty("TrustRoots",
                    this.trustRootsCheckBox.isSelected() ? "yes" : "no");
            this.properties.store(localFileOutputStream,
                    MyProxyLogonGUI.class.getName());
        } catch (FileNotFoundException localFileNotFoundException) {
            localFileNotFoundException.printStackTrace();
        } catch (IOException localIOException) {
            localIOException.printStackTrace();
        }
    }

    protected void loadProperties() {
        try {
            this.properties = new Properties();
            FileInputStream localFileInputStream = new FileInputStream(
                    System.getProperty("user.home") + "/.MyProxyLogon");
            this.properties.load(localFileInputStream);
        } catch (FileNotFoundException localFileNotFoundException) {
        } catch (IOException localIOException) {
            localIOException.printStackTrace();
        }
    }

    public static void createAndShowGUI() {
        JFrame localJFrame = new JFrame("MyProxyLogon 1.1");
        MyProxyLogonGUI localMyProxyLogonGUI = new MyProxyLogonGUI();
        localJFrame.setDefaultCloseOperation(3);
        localJFrame.add(localMyProxyLogonGUI);
        localJFrame.pack();
        localMyProxyLogonGUI.passwordField.requestFocusInWindow();
        localJFrame.setVisible(true);
    }

    private JTextField createField(String paramString1, String paramString2) {
        JTextField localJTextField = new JTextField(10);
        localJTextField.setActionCommand(paramString1);
        localJTextField.addActionListener(this);
        if (paramString2 != null) {
            localJTextField.setText(paramString2);
            localJTextField.setColumns(paramString2.length());
        }
        return localJTextField;
    }

    private JLabel createLabel(String paramString, Component paramComponent) {
        JLabel localJLabel = new JLabel(paramString + ": ");
        localJLabel.setLabelFor(paramComponent);
        return localJLabel;
    }

    private boolean verifyInput() {
        boolean bool = true;
        StringBuffer localStringBuffer = new StringBuffer();
        if (this.usernameField.getText().length() == 0) {
            bool = false;
            localStringBuffer.append("Please specify a username.\n");
        }
        if (this.passwordField.getPassword().length == 0) {
            bool = false;
            localStringBuffer.append("Enter passphrase to logon.\n");
        } else {
            this.myproxy.getClass();
            if (this.passwordField.getPassword().length < 6) {
                bool = false;
                localStringBuffer.append("Passphrase must be at least ");
                this.myproxy.getClass();
                localStringBuffer.append(Integer.toString(6));
                localStringBuffer.append(" characters in length.\n");
            }
        }
        if (this.lifetimeField.getText().length() == 0) {
            this.lifetimeField.setText(Integer.toString(this.myproxy
                    .getLifetime() / 3600));
        }
        try {
            Integer.parseInt(this.lifetimeField.getText());
        } catch (NumberFormatException localNumberFormatException1) {
            bool = false;
            localStringBuffer.append("Lifetime is not a valid integer.\n");
        }
        if (this.hostnameField.getText().length() == 0) {
            bool = false;
            localStringBuffer
                    .append("Please specify a MyProxy server hostname.\n");
        } else {
            try {
                InetAddress.getByName(this.hostnameField.getText());
            } catch (UnknownHostException localUnknownHostException) {
                bool = false;
                localStringBuffer.append("Hostname \"");
                localStringBuffer.append(this.hostnameField.getText());
                localStringBuffer
                        .append("\" is not valid. Please specify a valid MyProxy server hostname.\n");
            }
        }
        if (this.portField.getText().length() == 0) {
            this.portField.setText(Integer.toString(this.myproxy.getPort()));
        }
        try {
            Integer.parseInt(this.portField.getText());
        } catch (NumberFormatException localNumberFormatException2) {
            bool = false;
            localStringBuffer
                    .append("Port is not a valid integer. Please specify a valid MyProxy server port (default: 7514).\n");
        }
        if (this.outputField.getText().length() > 0) {
            File localFile = new File(this.outputField.getText());
            if ((localFile.exists()) && (!localFile.canWrite())) {
                bool = false;
                localStringBuffer.append(localFile.getPath());
                localStringBuffer
                        .append(" exists and is not writable. Please specify a valid output file or specify no output path to only perform authentication.\n");
            }
        }
        this.statusTextArea.setText(new String(localStringBuffer));
        return bool;
    }
}

/*
 * Location: /home/terryk/Workspaces/workESGF/ESGFToolsUI/lib/MyProxyLogon.jar
 * Qualified Name: edu.uiuc.ncsa.MyProxy.MyProxyLogonGUI Java Class Version: 6
 * (50.0) JD-Core Version: 0.7.0.1
 */
