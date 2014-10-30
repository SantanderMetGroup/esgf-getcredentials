package es.unican.meteo.esgf.myproxyclient;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import MyProxy.MyProxyLogon;
import es.unican.meteo.esgf.common.ESGFCredentials;

public class MyProxyLogonProvider implements MyProxyProvider {

	/** Logger. */
	static private org.slf4j.Logger LOG = org.slf4j.LoggerFactory
			.getLogger(MyProxyLogonProvider.class);

	public ESGFCredentials getESGFCredentials(boolean bootstrap,
			MyProxyParameters myProxyParams, String caDirectory)
			throws IOException, GeneralSecurityException {

		LOG.debug("Configuring X509_CERT_DIR and security providers...");
		// Clear value of X509_CERT_DIR and remove bouncy castle provider
		System.clearProperty("X509_CERT_DIR");
		Security.removeProvider("BC");

		// Configurate system
		if (!bootstrap) {
			System.setProperty("X509_CERT_DIR", caDirectory);
		}

		// for console debug
		// System.setProperty("javax.net.debug", "ssl");

		LOG.debug("Generating MyProxyLogon object..");
		MyProxyLogon myProxyLogon = getConnection(bootstrap, myProxyParams);

		LOG.debug("Retrieving credentials from the MyProxy server..");
		myProxyLogon.getCredentials();

		if (myProxyParams.isRequestTrustRoots()) {
			try {
				LOG.info("Writing trust roots to {}", caDirectory);
				myProxyLogon.writeTrustRoots(caDirectory);
				LOG.debug("Retrieved trust roots writed in " + caDirectory);
			} catch (IOException e) {
				LOG.error("Couldn't write certificates");
				throw e;
			}
		}

		LOG.debug("Generaring ESGF credentials..");
		// get user certificate and other certificates
		Collection<X509Certificate> x509Certificates = myProxyLogon
				.getCertificates();
		Iterator<X509Certificate> iter = x509Certificates.iterator();
		X509Certificate userCert = (X509Certificate) iter.next();
		x509Certificates.remove(userCert);

		// get private key
		PrivateKey privateKey = myProxyLogon.getPrivateKey();

		// ESGFCredentials
		return new ESGFCredentials(userCert, privateKey, x509Certificates);
	}

	/**
	 * Configure {@link MyProxyLogon}
	 * 
	 * @throws GeneralSecurityException
	 */
	private MyProxyLogon getConnection(boolean bootstrap,
			MyProxyParameters myProxyParams) throws GeneralSecurityException {

		MyProxyLogon myProxyLogon = new MyProxyLogon();
		myProxyLogon.setUsername(myProxyParams.getUserName());
		myProxyLogon.setPassphrase(myProxyParams.getPassword());
		myProxyLogon.setHost(myProxyParams.getHost());
		myProxyLogon.setPort(myProxyParams.getPort());
		myProxyLogon.setLifetime(myProxyParams.getLifetime());
		myProxyLogon.setBootstrap(bootstrap);
		myProxyLogon.requestTrustRoots(true); // always true

		LOG.debug("MyProxyLogon generated:{}", myProxyParams.toString());

		return myProxyLogon;
	}

}
