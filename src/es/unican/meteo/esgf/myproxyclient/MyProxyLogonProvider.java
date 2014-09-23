package es.unican.meteo.esgf.myproxyclient;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import edu.uiuc.ncsa.myproxy.MyProxyLogon;
import es.unican.meteo.esgf.common.ESGFCredentials;

public class MyProxyLogonProvider implements MyProxyProvider {
	
	/** Logger. */
    static private org.slf4j.Logger logger = org.slf4j.LoggerFactory
            .getLogger(MyProxyLogonProvider.class);
    
	
	public ESGFCredentials getESGFCredentials(MyProxyParameters myProxyParams, String caDirectory) throws IOException, GeneralSecurityException {
        // Configurate system
		System.clearProperty("X509_CERT_DIR");
        Security.removeProvider("BC");
        System.setProperty("X509_CERT_DIR", caDirectory);
        // System.setProperty("javax.net.debug", "ssl"); // for console debugging
        // ------------------------------------------------------------------
        
		logger.debug("Generating MyProxyLogon object..");
		MyProxyLogon myProxyLogon =getConnection(myProxyParams);
		
		logger.debug("Retrieving credentials from the MyProxy server..");
		myProxyLogon.getCredentials();
		
		if (myProxyParams.isRequestTrustRoots()) {
			try {
				logger.info("Writing trust roots to {}", caDirectory);
				myProxyLogon.writeTrustRoots(caDirectory);
				logger.debug("Retrieved trust roots writed in " + caDirectory);
			} catch (IOException e) {
				logger.error("Couldn't write certificates");
				throw e;
			}
		}
		
		logger.debug("Generaring ESGF credentials..");
		//get user certificate and other certificates
		Collection<X509Certificate> x509Certificates = myProxyLogon.getCertificates();
		Iterator<X509Certificate> iter = x509Certificates.iterator();
		X509Certificate userCert=(X509Certificate) iter.next();
		x509Certificates.remove(userCert);
		
		//get private key
		PrivateKey privateKey=myProxyLogon.getPrivateKey();
		
		//ESGFCredentials
		return new ESGFCredentials(userCert, privateKey, x509Certificates);
	}
	
	
	/**
     * Configure {@link MyProxyLogon}
	 * @throws GeneralSecurityException 
     */
	private MyProxyLogon getConnection(MyProxyParameters myProxyParams) throws GeneralSecurityException {
		logger.trace("[IN]  getConnection");

		MyProxyLogon myProxyLogon = new MyProxyLogon();
		myProxyLogon.setUsername(myProxyParams.getUserName());
		myProxyLogon.setPassphrase(myProxyParams.getPassword());
		myProxyLogon.setHost(myProxyParams.getHost());
		myProxyLogon.setPort(myProxyParams.getPort());
		myProxyLogon.setLifetime(myProxyParams.getLifetime());
		myProxyLogon.requestTrustRoots(true);
		logger.debug("MyProxyLogon generated:{}", myProxyParams.toString());
		
		logger.trace("[OUT] getConnection");
		return myProxyLogon;
	}
	
	
}
