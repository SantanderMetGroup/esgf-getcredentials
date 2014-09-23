package examples;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.StringWriter;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;

import org.bouncycastle.openssl.PEMReader;
import org.globus.myproxy.GetParams;
import org.globus.myproxy.MyProxy;
import org.gridforum.jgss.ExtendedGSSCredential;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.w3c.dom.Document;

public class RetrieveESGFCredentials {

    public static void main(String args[]) {
        String openIdURLStr = "";
        String passphrase = "";
        boolean success = true;

        try {
            System.out.print("OpenID URL:");
            BufferedReader br = new BufferedReader(new InputStreamReader(
                    System.in));

            openIdURLStr = br.readLine();

            System.out.print("Password:");
            br = new BufferedReader(new InputStreamReader(System.in));
            passphrase = br.readLine();
        } catch (IOException e2) {
            // TODO Auto-generated catch block
            e2.printStackTrace();
        }

        // Constants.
        final String KEYSTORE_NAME = "keystore.ks";
        final String FEDERATION_TRUSTSTORE_URL = "https://rainbow.llnl.gov/dist/certs/esg-truststore.ts";
        final String TEMP_X509_CERTIFICATES = "tempCert";
        final String PASSWORD = "changeit";
        final String TRUSTSTORE_FILE_NAME = "esg-truststore.ts";
        final String DEFAULT_ESG_FOLDER = ".esg2";
        final String ESG_HOME_ENV_VAR = "ESG_HOME2";
        final String SSLCONTEXT = "TLS";
        final String RSA_PRIVATE_KEY_PEM_FOOTER = "-----END RSA PRIVATE KEY-----";
        final String RSA_PRIVATE_KEY_PEM_HEADER = "-----BEGIN RSA PRIVATE KEY-----";
        final String CERTIFICATE_PEM_FOOTER = "-----END CERTIFICATE-----";
        final String CERTIFICATE_PEM_HEADER = "-----BEGIN CERTIFICATE-----";
        final int LIFE_TIME = 259200;

        System.out.println("Setting values for download..");
        GSSCredential credential = null;
        OutputStream out = null;
        String esgHome = null;

        // use ESG_HOME environmental variable if exists
        Map<String, String> env = System.getenv();
        if (env.containsKey(ESG_HOME_ENV_VAR)) {
            esgHome = env.get(ESG_HOME_ENV_VAR);
        } else { // use default directory if not
            String homePath = System.getProperty("user.home");
            esgHome = homePath + File.separator + DEFAULT_ESG_FOLDER;
        }
        System.out.println("..ESG_HOME=" + esgHome);

        // if .esg directory doesn't exist then create new
        File esgDirectory = new File(esgHome);
        if (!esgDirectory.exists()) {
            esgDirectory.mkdir();
            esgDirectory.setExecutable(true);
            esgDirectory.setReadable(true);
            esgDirectory.setWritable(true);
            System.out.println(".esg is created");
        }

        // System options: Add java security provider
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        // System options: Predetermine temp directory from x509 crtificates
        System.setProperty("X509_CERT_DIR", esgHome + File.separator
                + TEMP_X509_CERTIFICATES);
        String username = (openIdURLStr
                .substring(openIdURLStr.lastIndexOf("/") + 1));

        System.out.println("Getting connection with OpenID");

        try {
            System.out
                    .println("Establishing connection with OpenID and getting CA's trustStore");

            SSLContext context = null;
            HttpsURLConnection openIdConnection = null;

            try {
                System.out
                        .println("Creating new httpsUrlConnection to access openId info");

                // new secure HttpsURLConnection
                URL secureUrl = new URL(openIdURLStr);
                URLConnection sslConnection = secureUrl.openConnection();
                openIdConnection = (HttpsURLConnection) sslConnection;

                System.out.println("Getting keystore of CA from: {}"
                        + FEDERATION_TRUSTSTORE_URL);

                // Generate key store of trust CA. Load CA from ESGF URL
                KeyStore keyStore = KeyStore.getInstance(KeyStore
                        .getDefaultType());
                URL keyStoreURL = new URL(FEDERATION_TRUSTSTORE_URL);
                keyStore.load(keyStoreURL.openStream(), PASSWORD.toCharArray());

                // Generate trust store factory
                TrustManagerFactory tmf = TrustManagerFactory
                        .getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(keyStore);

                System.out.println("Saving keystore of CA's");
                keyStore.store(new BufferedOutputStream(new FileOutputStream(
                        new File(esgHome + File.separator
                                + TRUSTSTORE_FILE_NAME))), PASSWORD
                        .toCharArray());

                // SSL context with client certificates
                context = SSLContext.getInstance(SSLCONTEXT);
                context.init(null, tmf.getTrustManagers(), null);

                // Set ssl socket factory
                openIdConnection
                        .setSSLSocketFactory(context.getSocketFactory());
            } catch (Exception e) {
                System.out
                        .println("Error getting open id url connection: " + e);
                success = false;
            }

            openIdConnection.connect();
            System.out.println("OpenID XML document are retrieved");

            System.out.println("Reading XML document..");
            // read openId XML document
            InputStream localInputStream = openIdConnection.getInputStream();
            Document localDocument = DocumentBuilderFactory.newInstance()
                    .newDocumentBuilder().parse(localInputStream);

            System.out.println("Getting myproxy-service info..");
            // Get myproxy-service info
            DOMSource domSource = new DOMSource(localDocument);
            StringWriter writer = new StringWriter();
            StreamResult result = new StreamResult(writer);
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.transform(domSource, result);
            System.out.println("OpenID XML: \n" + writer.toString());

            System.out.println("Getting my proxy service from OpenId XML");
            // Get myproxy-service section in xml
            XPath localXPath = XPathFactory.newInstance().newXPath();
            XPathExpression localXPathExpression = localXPath
                    .compile("//*[Type='urn:esg:security:myproxy-service']/URI");
            String str = (String) localXPathExpression.evaluate(localDocument,
                    XPathConstants.STRING);
            String[] arrayOfString = str.split(":");
            String host = (arrayOfString[1].substring(2));
            int port = (Integer.parseInt(arrayOfString[2]));

            // Set new proxy
            GetParams params = new GetParams();
            params.setUserName(username);
            params.setPassphrase(passphrase);
            params.setWantTrustroots(false);
            params.setLifetime(LIFE_TIME);

            MyProxy myProxy = new MyProxy(host, port);
            myProxy.bootstrapTrust();
            System.out.println("New myProxy object with parameters: " + params
                    + ", " + "host:" + host + ", port:" + port);
            System.out.println("Get credentials of user with myProxy service");
            credential = myProxy.get(null, params);

        } catch (Exception e) {
            System.out.println("Error in retrive credentials: " + e);
            success = false;
        }

        // credentials.export give a credentials in .pem format
        // RSA key and certificate are in the same file
        byte[] data = null;
        try {
            data = ((ExtendedGSSCredential) credential)
                    .export(ExtendedGSSCredential.IMPEXP_OPAQUE);
        } catch (GSSException e1) {
            System.out.println("Error generating ExtendedGSSCredential");
            e1.printStackTrace();
            success = false;
        }

        // Create keystore: must be type JKS
        KeyStore keystore;
        try {
            System.out
                    .println("Generating X509Certificate from Credential in pem format");
            String pem = new String(data, "UTF-8");

            // Generate X509 certificate with PEMReader (org.bouncycastle)
            PEMReader reader;

            // Generate X509 certificate with PEMReader(org.bouncycastle)
            // Credential.pem have RSA key and certificate in the same
            // file and must be splitted
            System.out
                    .println("Get first fragment of pem (certificate) for get X509Certificate");
            reader = new PEMReader(new InputStreamReader(
                    new ByteArrayInputStream(getFragmentOfPEM(pem,
                            CERTIFICATE_PEM_HEADER, CERTIFICATE_PEM_FOOTER))));

            X509Certificate x509Certificate = (X509Certificate) reader
                    .readObject();
            System.out.println("X509Certificate has been generated:\n "
                    + x509Certificate);

            System.out
                    .println("Generating PrivateKey from Credential in pem format");
            System.out
                    .println("Get another fragment of pem (RSA key) for get PrivateKey");
            reader = new PEMReader(new InputStreamReader(
                    new ByteArrayInputStream(getFragmentOfPEM(pem,
                            RSA_PRIVATE_KEY_PEM_HEADER,
                            RSA_PRIVATE_KEY_PEM_FOOTER))));

            // PEMReader read a KeyPair class and then get the Private key
            KeyPair keyPair = (KeyPair) reader.readObject();
            PrivateKey key = keyPair.getPrivate();
            System.out.println("PrivateKey has been generated:\n {}" + key);

            keystore = KeyStore.getInstance(KeyStore.getDefaultType()); // JKS
            keystore.load(null);
            keystore.setCertificateEntry("cert-alias", x509Certificate);
            keystore.setKeyEntry("key-alias", key, "changeit".toCharArray(),
                    new Certificate[] { x509Certificate });
            System.out
                    .println("Generated key store of private key and X509Certificate.");
            // save credentials in keystore file
            keystore.store(new BufferedOutputStream(new FileOutputStream(
                    new File(esgHome + File.separator + KEYSTORE_NAME))),
                    PASSWORD.toCharArray());

        } catch (Exception e) {
            System.out.println("key store for netcdf isn't generated: " + e);
            success = false;
        }

        if (success) {
            System.out.println("Success!. Certificates are retrieved.");
        }
    }

    /**
     * Get fragment of PEM
     * 
     * @param pem
     *            PEM formatted data String
     * @param header
     *            DER data header
     * @param footer
     *            DER data footer
     * @return
     * @throws IllegalArgumentException
     *             if the PEM String does not contain the requested data
     */
    private static byte[] getFragmentOfPEM(String pem, String header,
            String footer) {
        String[] tokens1 = pem.split(header);
        if (tokens1.length < 2) {
            throw new IllegalArgumentException(
                    "The PEM data does not contain the requested header");
        }
        String[] tokens2 = tokens1[1].split(footer);
        tokens2[0] = header + tokens2[0] + footer;

        return tokens2[0].getBytes();
    }
}
