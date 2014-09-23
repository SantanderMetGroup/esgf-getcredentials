package es.unican.meteo.esgf.util;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

public class StoreUtil {

	/**
	 * Generate a keystore object of the JCEKS type.
	 * @param userCertificate
	 * @param privateKey
	 * @param otherCerts
	 * @param passwd
	 * @return
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	public static KeyStore generateJCEKSKeystore(X509Certificate userCertificate, 
			PrivateKey privateKey, Collection<X509Certificate> otherCerts, String passwd) 
					throws GeneralSecurityException, IOException {
		// certificates [] <- user certificate and others
		Iterator<X509Certificate> iter = otherCerts.iterator();
		X509Certificate[] certificates = new X509Certificate[otherCerts.size() + 1];
        certificates[0] = userCertificate;
        for (int i = 0; i < otherCerts.size(); i++) {
            certificates[i + 1] = (X509Certificate) iter.next();
        }
		
        //Create JCEKS keystore
		KeyStore keystore = KeyStore.getInstance("JCEKS");
        keystore.load(null);
        keystore.setCertificateEntry("cert-alias", userCertificate);
        keystore.setKeyEntry("key-alias", privateKey, passwd.toCharArray(),
                certificates);
        
		return keystore;
	}
	
	/**
	 * Generate a keystore object of the JKS type.
	 * @param userCertificate
	 * @param privateKey
	 * @param otherCerts
	 * @param passwd
	 * @return
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	public static KeyStore generateJKSKeystore(X509Certificate userCertificate, 
			PrivateKey privateKey, Collection<X509Certificate> otherCerts, String passwd) 
					throws GeneralSecurityException, IOException {
		// certificates [] <- user certificate and others
		Iterator<X509Certificate> iter = otherCerts.iterator();
		X509Certificate[] certificates = new X509Certificate[otherCerts.size() + 1];
		certificates[0] = userCertificate;
		for (int i = 0; i < otherCerts.size(); i++) {
			certificates[i + 1] = (X509Certificate) iter.next();
		}


		//Create JKS keystore
		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		keystore.load(null);
		keystore.setCertificateEntry("cert-alias", userCertificate);
		keystore.setKeyEntry("key-alias", privateKey, passwd.toCharArray(),
				certificates);

		return keystore;
	}
	
	/**
	 * Read a truststore from an input stream.
	 * @param truststoreInput input stream
	 * @param passwd password of truststore
	 * @return a {@link KeyStore} object of input trustore
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	public static KeyStore loadJKSTrustStore(InputStream truststoreInput, String passwd) 
			throws GeneralSecurityException, IOException{
		
        KeyStore truststore = KeyStore.getInstance(KeyStore
                .getDefaultType());// JKS
        
        if(passwd==null){
        	passwd="changeit"; //default pass
        }
        
        // load truststore from input stream
        truststore.load(truststoreInput, passwd.toCharArray());
        truststoreInput.close();
        
        return truststore;
	}
}
