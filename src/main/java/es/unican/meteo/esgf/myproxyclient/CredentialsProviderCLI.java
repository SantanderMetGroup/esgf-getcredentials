package es.unican.meteo.esgf.myproxyclient;

import java.awt.GraphicsEnvironment;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Map;
import java.util.Properties;
import java.util.ResourceBundle;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import org.docopt.Docopt;

import es.unican.meteo.esgf.myproxyclient.CredentialsProvider.Lib;

public final class CredentialsProviderCLI {

    private static final String GET_CRED_PROPERTIES = "getcredentials.properties";

    public static void main(final String[] args) throws Exception {

        CredentialsProvider credentialsProvider = CredentialsProvider
                .getInstance();

        // load properties file
        Properties getCredProperties = new Properties();
        InputStream is = CredentialsProvider.class.getClassLoader()
                .getResourceAsStream(GET_CRED_PROPERTIES);

        try {
            getCredProperties.load(is);
        } catch (IOException e) {
            e.printStackTrace();
            System.err.print("Error reading " + GET_CRED_PROPERTIES + " file");
        }

        String doc = ResourceBundle.getBundle("docopt")
                .getString("config");

        if (args.length < 1 && !GraphicsEnvironment.isHeadless()) {
            // usage: esgf-getcredentials

            // get nodes property that contains the nodes split by " "
            String strNodes = getCredProperties.getProperty("getcredentials.nodes");
            String[] nodes = strNodes.split(" ");
            CredentialsProviderGUI ui = new CredentialsProviderGUI(
                    credentialsProvider, nodes);

        } else {
            // usage: esgf-getcredentials (-o <openid> | --openid <openid>)
            // [options]

            Docopt docopt = new Docopt(doc);
            docopt.withVersion("esgf-getcredentials "
                    + getCredProperties.getProperty("getcredentials.version"));

            // parse the passed arguments returns a Map<String, Object>
            // except when --version or --help/-h options are passed
            final Map<String, Object> opts = docopt.parse(args);
            String openid = (String) opts.get("--openid");
            String password = (String) opts.get("--password");
            String outputCredPath = (String) opts.get("--output");
            String newKSPassword = (String) opts.get("--keystorepassw");
            boolean bootstrap = (Boolean) opts.get("--bootstrap");
            boolean debug = (Boolean) opts.get("--debug");
            boolean writeAll = (Boolean) opts.get("--writeall");

            // parse write options
            boolean writeTruststore, writeTrustroots = false;
            boolean writeJKSkeystore, writeJCEKSkeystore = false;
            boolean writeCacert, writeCredentials = false;
            if (writeAll) {
                writeTruststore = true;
                writeTrustroots = true;
                writeJKSkeystore = true;
                writeJCEKSkeystore = true;
                writeCacert = true;
                writeCredentials = true;
            } else {
                writeTruststore = (Boolean) opts.get("--cacertsjks");
                writeTrustroots = (Boolean) opts.get("--cacerts");
                writeJKSkeystore = (Boolean) opts.get("--keystorejks");
                writeJCEKSkeystore = (Boolean) opts.get("--keystorejceks");
                writeCacert = (Boolean) opts.get("--cacertspem");
                writeCredentials = (Boolean) opts.get("--credentials");
            }

            // always use my proxy logon
            credentialsProvider.setMyProxyLib(Lib.MYPROXYLOGON);

            // get password
            if (password == null) {
                if (System.console() != null) {
                    // in shell
                    password = new String(System.console()
                            .readPassword("Password: "));
                } else {
                    BufferedReader br = new BufferedReader(new InputStreamReader(
                            System.in));
                    System.out.print("Password: ");
                    br = new BufferedReader(new InputStreamReader(System.in));
                    password = br.readLine();
                }
            }

            // configure user openid
            credentialsProvider.setOpenID(openid, password.toCharArray());

            // configure options
            if (outputCredPath != null) {
                credentialsProvider.setCredentialsDirectory(outputCredPath);
            }
            if (newKSPassword != null) {
                credentialsProvider.setKeystorePass(newKSPassword);
            }
            credentialsProvider.setBootstrap(bootstrap);
            credentialsProvider.setWriteCaCertsPem(writeCacert);
            credentialsProvider.setWriteJCEKSKeystore(writeJCEKSkeystore);
            credentialsProvider.setWriteJKSKeystore(writeJKSkeystore);
            credentialsProvider.setWritePem(writeCredentials);
            credentialsProvider.setWriteTrustRootsCerts(writeTrustroots);
            credentialsProvider.setWriteTruststore(writeTruststore);

            // if debug put logger in FINE Level (debug)
            // (There is no way to do this with slf4j
            // http://bugzilla.slf4j.org/show_bug.cgi?id=206)
            if (debug) {
                Logger rootlogger = java.util.logging.Logger.getLogger("");
                rootlogger.setLevel(java.util.logging.Level.FINEST);
                org.apache.log4j.LogManager.getRootLogger().setLevel(
                        org.apache.log4j.Level.DEBUG);
            } else {
                // remove all logger levels < Severe (There is no way to do this
                // with slf4j http://bugzilla.slf4j.org/show_bug.cgi?id=206)
                for (String name : LogManager.getLoggingMXBean()
                        .getLoggerNames()) {
                    LogManager.getLoggingMXBean()
                            .setLoggerLevel(name, "SEVERE");
                }
            }

            // get credentials
            credentialsProvider.retrieveCredentials();

            System.out.println("Success!");
            System.out.println("The follow files have been written in "
                    + credentialsProvider.getCredentialsDirectory());

            if (writeCredentials) {
                System.out.println("- User certificate and private"
                        + " key in pem format");
            }
            if (writeCacert) {
                System.out.println("- Trust CA certificates in pem format");
            }
            if (writeTruststore) {
                System.out
                        .println("- Trust CA certificates in JKS keystore format");
            }
            if (writeTrustroots) {
                System.out.println("- Trust CA certificates in a folder");
            }
            if (writeJKSkeystore) {
                System.out
                        .println("- JKS keystore file. This keystore contains certificate,"
                                + " certificate chain and private key of user");
            }
            if (writeJCEKSkeystore) {
                System.out
                        .println("- JCEKS keystore file. This keystore contains certificate,"
                                + " certificate chain and private key of user");
            }
        }
    }
}
