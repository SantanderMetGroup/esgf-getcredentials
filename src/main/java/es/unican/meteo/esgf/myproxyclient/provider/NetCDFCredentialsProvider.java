package es.unican.meteo.esgf.myproxyclient.provider;

import java.io.File;
import java.io.IOException;
import java.security.KeyStore;

import es.unican.meteo.esgf.myproxyclient.CredentialsProvider;
import ucar.nc2.util.net.HTTPAuthScheme;
import ucar.nc2.util.net.HTTPSSLProvider;
import ucar.nc2.util.net.HTTPSession;

public class NetCDFCredentialsProvider {

	private static final String KEYSTORE_FILE = "keystore_jks.ks";
	private static final String TRUSTSTORE_FILE = "esg-truststore.ts";

	/**
	 * Configure {@link HTTPSession}.
	 * 
	 * @param openID openID URL
	 * @param password password of openID account
	 * @throws IOException 
	 */
	public static void configureCredentialsInNetCDF(String openID, String password) throws IOException{

		HTTPSSLProvider sslProvider=null;
		try {
			sslProvider = getSSLCredentialsProvider(openID, password);
		} catch (Exception e) {
			throw new IOException(e.getCause()+"ESGF Credentials couldn't be configured in NetCDF");
		}
		HTTPSession.setAnyCredentialsProvider(HTTPAuthScheme.SSL,
				null, sslProvider);
	}

	/**
	 * Get {@link HTTPSSLProvider} for ESGF.
	 * 
	 * @param openID openID URL
	 * @param password password of openID account
	 * @return
	 * @throws IOException 
	 */
	public static HTTPSSLProvider getSSLCredentialsProvider(String openID, String password) throws IOException{

		String esgNetCDFPath=System.getProperty("user.home")+ File.separator + ".esgNetCDF";

		CredentialsProvider esgfCredProvider= CredentialsProvider.getInstance();
		esgfCredProvider.setCredentialsDirectory(esgNetCDFPath);
		esgfCredProvider.setOpenID(openID, password.toCharArray());

		esgfCredProvider.setWriteJKSKeystore(true);
		esgfCredProvider.setWriteTruststore(true);

		try {
			esgfCredProvider.retrieveCredentials();
		} catch (Exception e) {
			throw new IOException(e.getCause()+"ESGF Credentials couldn't be retrieved from ESGF. OpenID: "+openID);
		}

		String keystore = esgNetCDFPath + File.separator + KEYSTORE_FILE;
		String truststore = esgNetCDFPath + File.separator +TRUSTSTORE_FILE;


		HTTPSSLProvider sslProvider = new HTTPSSLProvider(keystore, "changeit", truststore,
				"changeit");

		return sslProvider;

	}

	/**
	 * Get {@link HTTPSSLProvider} for ESGF.
	 * 
	 * @param keystore key storage (JKS) facility for cryptographic keys and certificates.
	 * @param keypass keystore password
	 * @param truststore keystore of CA certificates 
	 * @param trustpass trustore passsword
	 * @return
	 */
	public static HTTPSSLProvider getSSLCredentialsProvider(String keystore, String keypass, String truststore, String trustpass) {

		HTTPSSLProvider sslProvider = new HTTPSSLProvider(keystore, keypass, truststore,
				trustpass);
		return sslProvider;

	}


}
