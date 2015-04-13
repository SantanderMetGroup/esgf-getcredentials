package es.unican.meteo.esgf.common;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.LinkedList;

/**
 * ESGF credentials. Contains the temporal x509 user certificate, the temporal
 * user RSA private key, and may content x509 server certificates.
 * 
 * @author Karem Terry
 *
 */
public class ESGFCredentials {

    /** Temporal user certificate. */
    private X509Certificate x509userCertificate;
    /** User RSA private key. */
    private PrivateKey privateKey;
    /** Server certificates. */
    private Collection<X509Certificate> x509ServerCertificates;

    /**
     * Constructor
     * 
     * @param x509userCertificate
     *            user x509 certificate
     * @param privateKey
     *            user RSA private key
     * @param x509ServerCertificates
     *            server certificates
     */
    public ESGFCredentials(X509Certificate x509userCertificate,
            PrivateKey privateKey,
            Collection<X509Certificate> x509ServerCertificates) {
        this.x509userCertificate = x509userCertificate;
        this.privateKey = privateKey;
        this.x509ServerCertificates = x509ServerCertificates;
    }

    /**
     * Gets the x509 user certificate.
     * 
     * @return the x509 user certificate
     */
    public X509Certificate getX509userCertificate() {
        return x509userCertificate;
    }

    /**
     * Gets the RSA private key.
     * 
     * @return the privateKey
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * Gets the server certificates.
     * 
     * @return {@link X509Certificate}
     */
    public Collection<X509Certificate> getX509ServerCertificates() {
        return x509ServerCertificates;
    }

    /**
     * Sets the x509 user certificate.
     * 
     * @param x509userCertificate
     *            the x509 user certificate to set
     */
    public void setX509userCertificate(X509Certificate x509userCertificate) {
        this.x509userCertificate = x509userCertificate;
    }

    /**
     * Sets the user RSA private key.
     * 
     * @param privateKey
     *            user RSA private key
     */
    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    /**
     * Sets the x509 server certificates
     * 
     * @param x509ServerCertificates
     */
    public void setX509CasCertificates(
            Collection<X509Certificate> x509ServerCertificates) {
        this.x509ServerCertificates = x509ServerCertificates;
    }

    /**
     * Get a collection with the user certificates and other certificates if
     * exists
     * 
     * @return
     */
    public Collection<X509Certificate> getAllx509Certificates() {

        Collection<X509Certificate> certificates = new LinkedList<X509Certificate>();
        certificates.add(x509userCertificate);
        certificates.addAll(x509ServerCertificates);

        return certificates;
    }
}
