package es.unican.meteo.esgf.myproxyclient;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.LinkedList;

import org.globus.myproxy.GetParams;
import org.globus.myproxy.MyProxy;
import org.globus.myproxy.MyProxyException;
import org.gridforum.jgss.ExtendedGSSCredential;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;

import es.unican.meteo.esgf.common.ESGFCredentials;
import es.unican.meteo.esgf.util.PemUtil;

public class MyProxy206Provider implements MyProxyProvider {

	/** Logger. */
	static private org.slf4j.Logger LOG = org.slf4j.LoggerFactory
			.getLogger(MyProxy206Provider.class);

	public ESGFCredentials getESGFCredentials(boolean bootstrap,
			MyProxyParameters myProxyParams, String caDirectory)
			throws IOException, GeneralSecurityException {

		LOG.debug("Configuring X509_CERT_DIR and security providers...");
		// Clear value of X509_CERT_DIR
		System.clearProperty("X509_CERT_DIR");
		// Set new value in X509_CERT_DIR property
		if (bootstrap) {
			System.setProperty("X509_CERT_DIR", caDirectory + File.separator
					+ "tempCerts");
		} else {
			System.setProperty("X509_CERT_DIR", caDirectory);
		}
		// Add java security provider
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		// for console debugging
		// System.setProperty("javax.net.debug", "ssl");

		LOG.debug("Getting GSSCredentials from MyProxy service...");
		GSSCredential credential;
		try {
			credential = getConnection(bootstrap, myProxyParams, caDirectory);
			byte[] data = ((ExtendedGSSCredential) credential)
					.export(ExtendedGSSCredential.IMPEXP_OPAQUE);
			String pem = new String(data);

			LOG.debug("Generaring ESGF credentials..");
			// get user certificate and other certificates
			X509Certificate[] certificates = PemUtil.getX509Certificates(pem);
			X509Certificate userCert = certificates[0];
			Collection<X509Certificate> x509Certificates = new LinkedList<X509Certificate>();
			for (int i = 1; i < certificates.length; i++) {
				x509Certificates.add(certificates[i]);
			}

			// get private key
			PrivateKey privateKey = PemUtil.getPrivateKey(pem);
			// ESGFCredentials
			return new ESGFCredentials(userCert, privateKey, x509Certificates);
		} catch (MyProxyException e) {
			e.printStackTrace();
			throw new GeneralSecurityException(e.getMessage(), e.getCause());
		} catch (GSSException e) {
			throw new GeneralSecurityException(e.getMessage(), e.getCause());
		}
	}

	/**
	 * Configure {@link MyProxy}
	 * 
	 * @throws MyProxyException
	 * @throws IOException
	 */
	private GSSCredential getConnection(boolean bootstrap,
			MyProxyParameters myProxyParams, String caDirectory)
			throws MyProxyException, IOException {

		String host = myProxyParams.getHost();
		int port = myProxyParams.getPort();

		// Set new proxy
		GetParams params = new GetParams();
		params.setUserName(myProxyParams.getUserName());
		params.setPassphrase(myProxyParams.getPassword());
		params.setWantTrustroots(myProxyParams.isRequestTrustRoots());
		params.setLifetime(myProxyParams.getLifetime());
		MyProxy myProxy = new MyProxy(host, port);
		if (bootstrap) {
			myProxy.bootstrapTrust();
		}
		LOG.debug("New myProxy object generated with parameters: {}, {}",
				params, "host:" + host + ", port:" + port);

		LOG.debug("Retrieving credentials from the MyProxy server..");
		GSSCredential credential = myProxy.get(null, params);

		if (myProxyParams.isRequestTrustRoots()) {
			LOG.info("Writing trust roots to {}", caDirectory);
			myProxy.writeTrustRoots(caDirectory);
		}

		return credential;
	}

}
