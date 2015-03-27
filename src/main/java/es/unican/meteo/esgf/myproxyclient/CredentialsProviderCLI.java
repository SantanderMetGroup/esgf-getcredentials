package es.unican.meteo.esgf.myproxyclient;

import java.awt.GraphicsEnvironment;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Map;
import java.util.Properties;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import org.docopt.Docopt;

import es.unican.meteo.esgf.myproxyclient.CredentialsProvider.Lib;

public final class CredentialsProviderCLI {

	private static final String ESGF_NODES_PROP = "getcredentials.properties";

	public static void main(final String[] args) throws Exception {

		CredentialsProvider credentialsProvider = CredentialsProvider
				.getInstance();

		String esgPath = credentialsProvider.getCredentialsDirectory();
		final String doc = "esgf-getcredentials.\n"
				+ "\n"
				+ "Usage:\n"
				+ " esgf-getcredentials\n"
				+ " esgf-getcredentials (-o <openid> | --openid <openid>) [options]\n"
				+ " esgf-getcredentials (-h | --help)\n"
				+ " esgf-getcredentials --version\n"
				+ "Options:\n"
				+ " -o <openid> --openid <openid>  OpenID endpoint from where myproxy information can be gathered.\n"
				+ " -p <password> --password <password>        OpenID passphrase.\n"
				+ " --output <path>                 Path of folder where the retrieved certificates will be stored"
				+ "[default: "
				+ esgPath
				+ "].\n"
				+ " -w --writeall                   Generate all credentials files. The files generated are the same"
				+ " files generated with opts: --credentials --cacertspem --cacertsjks --cacerts --jkskeystore --jcekskeystore\n"
				+ " -b --bootstrap                  To bootstrapping certificates in myproxy service.\n"
				+ " --credentials                   Write user certificate and private key in pem format.\n"
				+ " --cacertspem                    Write trust CA certificates in pem format.\n"
				+ " --cacertsjks                    Write trust CA certificates in JKS keystore format.\n"
				+ " --cacerts                       Write trust CA certificates in a folder.\n"
				+ " --keystorejks                   Write JKS keystore file. This keystore contains certificate,"
				+ " certificate chain and private key of user\n"
				+ " --keystorejceks                 Write JCEKS keystore file. This keystore contains certificate,"
				+ " certificate chain and private key of user\n"
				+ " -d --debug                      Turn debugging info on.\n"
				+ " -h --help                       Show this screen.\n"
				+ " --version                       Show version.\n" + "\n";

		if (args.length < 1 && !GraphicsEnvironment.isHeadless()) {
			// usage: esgf-getcredentials

			InputStream is =  CredentialsProvider.class.getClassLoader().getResourceAsStream(ESGF_NODES_PROP);

			Properties esgfNodes = new Properties();
			
			try {
				esgfNodes.load(is);
			} catch (IOException e) {
				e.printStackTrace();
				System.err.print("Error reading "+ ESGF_NODES_PROP+" file");
			}
			
			//get nodes property that contains the nodes split by " "
			String strNodes = esgfNodes.getProperty("getcredentials.nodes");
			String[] nodes = strNodes.split(" "); 
			CredentialsProviderGUI ui = new CredentialsProviderGUI(
					credentialsProvider, nodes);
		

			
		} else {
			// usage: esgf-getcredentials (-o <openid> | --openid <openid>)
			// [options]

			Docopt docopt = new Docopt(doc);
			docopt.withVersion("esgf-getcredentials 0.1");

			// parse the passed arguments returns a Map<String, Object>
			// except when --version or --help/-h options are passed
			final Map<String, Object> opts = docopt.parse(args);
			String openid = (String) opts.get("--openid");
			String password = (String) opts.get("--password");
			String outputCredPath = (String) opts.get("--output");
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
				if(System.console()!=null ){
					password = System.console().readPassword("Password: ").toString();
				}else{				
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
					+ outputCredPath);

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
