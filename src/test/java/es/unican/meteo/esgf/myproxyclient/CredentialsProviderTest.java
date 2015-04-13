package es.unican.meteo.esgf.myproxyclient;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ResourceBundle;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import es.unican.meteo.esgf.common.ESGFCredentials;

/**
 * JUnit test of es.unican.meteo.esgf.myproxyclient.CredentialsProvider
 * 
 * @author Karem Terry
 *
 */
public class CredentialsProviderTest {

    private static CredentialsProvider credentialsProvider;

    /**
     * This method is executed once, before the start of all tests.
     * 
     * Initialize credentialProvider and read the user-passsword from
     * res/authtest.properties directory to use in this test.
     * 
     * @throws java.lang.Exception
     */
    @BeforeClass
    public static void setUpBeforeClass() throws Exception {

        // init credential provider
        credentialsProvider = CredentialsProvider.getInstance();

        // read user-password from authtest.properties
        ResourceBundle rs = ResourceBundle.getBundle("authtest");
        String openID = rs.getString("auth.openid");
        String password = rs.getString("auth.password");

        assertFalse(
                "OpenID account isn't given in src/test/java/resources/authtest.properties",
                openID == null || openID.equals("") || openID.equals("empty"));
        assertFalse(
                "Password isn't given in src/test/java/resources/authtest.properties",
                password == null || password.equals("")
                        || password.equals("empty"));

        // set openID
        credentialsProvider.setOpenID(openID, password.toCharArray());

        // set test (default directories, set write all documents)
        credentialsProvider.setWriteCaCertsPem(true);
        credentialsProvider.setWriteJCEKSKeystore(true);
        credentialsProvider.setWriteJKSKeystore(true);
        credentialsProvider.setWritePem(true);
        credentialsProvider.setWriteTrustRootsCerts(true);
        credentialsProvider.setWriteTruststore(true);
    }

    /**
     * This method is executed once, after all tests have been finished.
     * 
     * @throws java.lang.Exception
     */
    @AfterClass
    public static void tearDownAfterClass() throws Exception {
    }

    /**
     * This method is executed once before each test
     * 
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {
    }

    /**
     * This method is executed once after each test
     * 
     * @throws java.lang.Exception
     */
    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void testGetCredentialsWithMyProxyLogon() throws Exception {

        // configure credentials provider
        credentialsProvider.setMyProxyLib(CredentialsProvider.Lib.MYPROXYLOGON);
        credentialsProvider.setBootstrap(false);

        // retrieve credentials
        ESGFCredentials credentials = credentialsProvider.retrieveCredentials();

        assertFalse("ESGF Credentials can't be retrieved", credentials == null);
        boolean valid = true;
        try {
            credentials.getX509userCertificate().checkValidity();
        } catch (Exception e) {
            valid = false;
        }
        assertTrue("X509 user certificate isn't valid", valid);
    }

    @Test
    public void testGetCredentialsWithMyProxyLogonAndBootstrap()
            throws Exception {

        // configure credentials provider
        credentialsProvider.setMyProxyLib(CredentialsProvider.Lib.MYPROXYLOGON);
        credentialsProvider.setBootstrap(true);

        // retrieve credentials
        ESGFCredentials credentials = credentialsProvider.retrieveCredentials();

        assertFalse("ESGF Credentials can't be retrieved", credentials == null);
        boolean valid = true;
        try {
            credentials.getX509userCertificate().checkValidity();
        } catch (Exception e) {
            valid = false;
        }
        assertTrue("X509 user certificate isn't valid", valid);
    }

    @Ignore
    public void testGetCredentialsWithMyProxy206() throws Exception {

        // configure credentials provider
        credentialsProvider.setMyProxyLib(CredentialsProvider.Lib.MYPROXYV206);
        credentialsProvider.setBootstrap(false);

        // retrieve credentials
        ESGFCredentials credentials = credentialsProvider.retrieveCredentials();

        assertFalse("ESGF Credentials can't be retrieved", credentials == null);
        boolean valid = true;
        try {
            credentials.getX509userCertificate().checkValidity();
        } catch (Exception e) {
            valid = false;
        }
        assertTrue("X509 user certificate isn't valid", valid);
    }

    @Ignore
    public void testGetCredentialsWithMyProxy206AndBootstrap() throws Exception {

        // Set MyProxy v 2.0.6
        credentialsProvider.setMyProxyLib(CredentialsProvider.Lib.MYPROXYV206);
        credentialsProvider.setBootstrap(true);

        // retrieve credentials
        ESGFCredentials credentials = credentialsProvider.retrieveCredentials();

        assertFalse("ESGF Credentials can't be retrieved", credentials == null);
        boolean valid = true;
        try {
            credentials.getX509userCertificate().checkValidity();
        } catch (Exception e) {
            valid = false;
        }
        assertTrue("X509 user certificate isn't valid", valid);
    }
}
