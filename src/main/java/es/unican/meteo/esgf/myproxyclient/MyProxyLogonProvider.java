package es.unican.meteo.esgf.myproxyclient;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

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
		try{
			myProxyLogon.getCredentials();
		}catch(SSLHandshakeException e){
			//Avoid "CN doesn't match server name" issue: the OpenID indicates 
			//that the MyProxy authentication service is located at some host and
			//port (usually 7512), but then, this host and port, in some cases, 
			//have a certificate with a subject that does not match the server host
			//name (and without any alternative subject name). 
			//Therefore, the SSL connection fails.
			try {
				LOG.warn(e.getMessage());
				
				//Replace host for its canonical host name
				InetAddress inetAddress=InetAddress.getByName(myProxyParams.getHost());
			    myProxyLogon.setHost(inetAddress.getCanonicalHostName());
			    myProxyLogon.getCredentials();
			} catch (UnknownHostException e1) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

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

		//Avoid "CN doesn't match server name" issue: the OpenID indicates 
		//that the MyProxy authentication service is located at some host and
		//port (usually 7512), but then, this host and port, in some cases, 
		//have a certificate with a subject that does not match the server host
		//name (and without any alternative subject name). 
		//Therefore, the SSL connection fails.
		try {
			InetAddress inetAddress=InetAddress.getByName(myProxyParams.getHost());
		  //  myProxyLogon.setHost(inetAddress.getCanonicalHostName());
			myProxyLogon.setHost(myProxyParams.getHost());
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		myProxyLogon.setPort(myProxyParams.getPort());
		myProxyLogon.setLifetime(myProxyParams.getLifetime());
		myProxyLogon.setBootstrap(bootstrap);
		myProxyLogon.requestTrustRoots(true); // always true

		LOG.debug("MyProxyLogon generated:{}", myProxyParams.toString());

		return myProxyLogon;
	}

}
