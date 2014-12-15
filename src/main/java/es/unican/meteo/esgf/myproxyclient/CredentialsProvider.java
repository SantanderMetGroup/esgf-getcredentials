/**
 * 
 */
package es.unican.meteo.esgf.myproxyclient;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.PasswordAuthentication;
import java.net.URL;
import java.net.URLConnection;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.compress.archivers.ArchiveException;
import org.apache.commons.compress.archivers.ArchiveStreamFactory;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.utils.IOUtils;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import es.unican.meteo.esgf.common.ESGFCredentials;
import es.unican.meteo.esgf.util.PemUtil;
import es.unican.meteo.esgf.util.StoreUtil;

/**
 * This class allows retrieve user credentials from ESGF. Also can write this
 * credentials in a file system in different forms. The default behavior is not
 * bootstrap the certificates and not write files. Singleton class.
 * 
 * <p>
 * For configure:
 * </p>
 * <ul>
 * <li>First get the instance of the class:
 * <ul>
 * <li>
 * <code> credencialsProvider = ESGFCredentialsProvider.getInstance()</code></li>
 * </ul>
 * </li>
 * <li>Second, set OpenID with user OpenID URL and password:
 * <ul>
 * <li>
 * <code>credentialsProvider.setOpenID(openID,password)</code></li>
 * </ul>
 * </li>
 * <li>By default {@link CredentialsProvider} isn't configured for write
 * credentials in file system. For configured it:
 * <ul>
 * <li>Write certificates in .pem format:
 * <code>credentialsProvider.setWritePem(true)</code></li>
 * <li>Write JKS keystore file:
 * <code>credentialsProvider.setWriteJKSKeystore(true)</code></li>
 * <li>Write JCEKS keystore file:
 * <code>credentialsProvider.setWriteJCEKSKeystore(true)</code></li>
 * <li>Write trustore in keystore format:
 * <code>credentialsProvider.setWriteTruststore(true)</code></li>
 * <li>Write all certificates trustroots in caDirectory:
 * <code>credentialsProvider.setWriteTrustRootsCerts(true)</code></li>
 * <li>Write esgf CA certificates in pem format:
 * <code>credentialsProvider.setWriteCaCertsPem(true)</code></li>
 * </ul>
 * </li>
 * </ul>
 * 
 * <p>
 * Advanced settings
 * </p>
 * <ul>
 * <li>Change default lib:
 * <code>credentialsProvider.setMyProxyLib(ESGFCredentialsProvider.Lib.MYPROXYV206)</code>
 * </li>
 * <li>Configure bootstrap, true for bootstrapping and false otherwise:
 * <code>credentialsProvider.setBootstrap(boolean)</code></li>
 * </ul>
 * 
 * @author Karem Terry
 */
public class CredentialsProvider {

	/** Logger. */
	static private org.slf4j.Logger LOG = org.slf4j.LoggerFactory
			.getLogger(CredentialsProvider.class);

	// Constants.
	private static final String FEDERATION_TRUSTSTORE_URL = "https://raw.github.com/ESGF/esgf-dist/master/installer/certs/esg-truststore.ts";
	private static final String ESGF_CA_CERTS_URL = "https://raw.githubusercontent.com/ESGF/esgf-dist/master/installer/certs/esg_trusted_certificates.tar";
	private static final String KEYSTORE_PASSWORD = "changeit";
	private static final int LIFE_TIME = 259200;
	private static final String SSLCONTEXT = "TLS";
	private static final String TRUSTSTORE_FILE = "esg-truststore.ts";
	private static final String CREDENTIALS_FILE_PEM = "credentials.pem";
	private static final String DEFAULT_ESG_FOLDER = ".esg";
	private static final String ESG_HOME_ENV_VAR = "ESG_HOME";
	private static final String KEYSTORE_JKS_FILE = "keystore_jks.ks";
	private static final String KEYSTORE_JCEKS_FILE = "keystore_jceks.ks";
	private static final String CA_DIRECTORY = "certificates";
	private static final String CAS_CERTIFICATES_PEM = "ca-certificates.pem";

	public enum Lib {
		/** myproxy-logon */
		MYPROXYLOGON,
		/** myproxy */
		MYPROXYV206;
	}

	/** Path user's folder for ESG credentials. */
	private static String esgHome;
	/** Path of directory of trust roots certs. */
	private String caDirectory;
	/** Singleton instance. */
	private static CredentialsProvider INSTANCE = null;
	/** OpenID account. */
	private PasswordAuthentication openID;
	/** ESGF Credentials. */
	private ESGFCredentials esgfCredentials;
	/** Boolean that indicates if bootstrapping certificates or not. */
	private boolean bootstrap;
	/** Boolean, indicates if write certificates in .pem format */
	private boolean writePem;
	/** Boolean that indicates if write JKS keystore file. */
	private boolean writeJKSKeystore;
	/** Boolean that indicates if write JCEKS keystore file. */
	private boolean writeJCEKSKeystore;
	/**
	 * Boolean that indicates if write all certificates trustroots in
	 * caDirectory.
	 */
	private boolean writeTrustRootsCerts;
	/** Boolean that indicates if trustore keystore (esg-trustore.ts). */
	private boolean writeTruststore;
	/** Boolean that indicates if write esgf CA certificates. */
	private boolean writeCaCertsPem;
	/** Library of MyProxyProvider. */
	private Lib myProxyLib = Lib.MYPROXYLOGON;// default lib for myproxy

	/**
	 * Create a thread-safe singleton.
	 */
	private static void createInstance() {
		LOG.trace("[IN]  createInstance");

		LOG.debug("Checking if exist an instance of ESGFCredentialsProvider");
		// creating a thread-safe singleton
		if (INSTANCE == null) {

			// Only the synchronized block is accessed when the instance hasn't
			// been created.
			synchronized (CredentialsProvider.class) {
				// Inside the block it must check again that the instance has
				// not been created.
				if (INSTANCE == null) {
					LOG.debug("Creating new instance of ESGFCredentialsProvider");
					INSTANCE = new CredentialsProvider();
				}
			}
		}
		LOG.trace("[OUT] createInstance");
	}

	/**
	 * Get singleton instance of {@link CredentialsProvider}. This instance is
	 * the only that exists.
	 * 
	 * @return the unique instance of {@link ESGFCredentialsProviders}.
	 */
	public static CredentialsProvider getInstance() {
		LOG.trace("[IN]  getInstance");
		createInstance();
		LOG.trace("[OUT] getInstance");
		return INSTANCE;
	}

	/**
	 * Constructor. Creates the ESGF credentials provider. If the user has a
	 * ESG_HOME environment variable set, then it is used as the folder to store
	 * the ESG credentials; otherwise, the default folder (&lt;user home
	 * folder&gt;/.esg) is used.
	 */
	private CredentialsProvider() {
		LOG.trace("[IN]  ESGFCredentialsProvider");
		// use ESG_HOME environmental variable if exists
		Map<String, String> env = System.getenv();
		if (env.containsKey(ESG_HOME_ENV_VAR)) {
			this.esgHome = env.get(ESG_HOME_ENV_VAR);
			this.caDirectory = esgHome + File.separator + CA_DIRECTORY;
		} else { // use default directory if not
			String homePath = System.getProperty("user.home");
			this.esgHome = homePath + File.separator + DEFAULT_ESG_FOLDER;
			this.caDirectory = esgHome + File.separator + CA_DIRECTORY;
		}

		openID = null;
		esgfCredentials = null;
		myProxyLib = Lib.MYPROXYLOGON;// default lib for myproxy
		// set java property to use TLSv1 only
		System.setProperty("https.protocols", "TLSv1");

		LOG.trace("[OUT] ESGFCredentialsProvider");
	}

	/**
	 * Get the directory where the credentials will be retrieved
	 * 
	 * @return directory where the credentials will be retrieved
	 */
	public String getCredentialsDirectory() {
		return esgHome;
	}

	/**
	 * Set user openID and password.
	 * 
	 * @param openIDURL
	 *            OpenID-enabled URL that can be used to log into OpenID-enabled
	 *            websites
	 * @param password
	 *            OpenID password
	 * @throws IOException
	 *             if some error happens getting credentials
	 */
	public synchronized void setOpenID(String openIDURL, char[] password)
			throws IOException {
		LOG.trace("[IN]  setOpenID");
		openID = new PasswordAuthentication(openIDURL, password);

		LOG.trace("[OUT] setOpenID");
	}

	/**
	 * Gets directory of trust roots certs.
	 * 
	 * @return the caDirectory
	 */
	public String getCaDirectoryPath() {
		return caDirectory;
	}

	/**
	 * Sets folder name of trust roots certs.
	 * 
	 * @param caDirectory
	 *            theory path direct
	 */
	public void setCaDirectoryName(String folderName) {
		this.caDirectory = esgHome + File.separator + folderName;
	}

	/**
	 * Returns true if bootstrapping certificates and false otherwise
	 * 
	 * @return
	 */
	public boolean isBootstrap() {
		return bootstrap;
	}

	/**
	 * Sets a boolean that indicates if bootstrapping certificates or not
	 * 
	 * @param bootstrap
	 *            true to bootstrapping certificates and false otherwise
	 */
	public void setBootstrap(boolean bootstrap) {
		this.bootstrap = bootstrap;
	}

	/**
	 * Return true if trustroots certificates will be written in a pem format.
	 * 
	 * @return the writeCaCertsPem
	 */
	public boolean isWriteCaCertsPem() {
		return writeCaCertsPem;
	}

	/**
	 * Return true if credentials will be written in JCEKS keystore.
	 * 
	 * @return the writeJCEKSKeystore
	 */
	public boolean isWriteJCEKSKeystore() {
		return writeJCEKSKeystore;
	}

	/**
	 * Return true if credentials will be written in JKS keystore.
	 * 
	 * @return the writeJKSKeystore
	 */
	public boolean isWriteJKSKeystore() {
		return writeJKSKeystore;
	}

	/**
	 * Return true if credentials will be written in a pem format.
	 * 
	 * @return the writePem
	 */
	public boolean isWritePem() {
		return writePem;
	}

	/**
	 * Return true if trustroots certificates will be written in a directory.
	 * 
	 * @param requestTrustRoots
	 *            the requestTrustRoots to set
	 */
	public boolean isWriteTrustRootsCerts() {
		return writeTrustRootsCerts;
	}

	/**
	 * Return true if truststore will be written in a file.
	 * 
	 * @return the writeTruststore
	 */
	public boolean isWriteTruststore() {
		return writeTruststore;
	}

	/**
	 * Reset credentials directory to the value of ESG_HOME environment variable
	 * if is set; otherwise, the default folder (&lt;user home folder&gt;/.esg)
	 * is used.
	 * 
	 */
	public void resetCredentialsDirectory() {
		// use ESG_HOME environmental variable if exists
		Map<String, String> env = System.getenv();

		if (env.containsKey(ESG_HOME_ENV_VAR)) {
			this.esgHome = env.get(ESG_HOME_ENV_VAR);
			this.caDirectory = esgHome + File.separator + CA_DIRECTORY;
		} else { // use default directory if not
			String homePath = System.getProperty("user.home");
			this.esgHome = homePath + File.separator + DEFAULT_ESG_FOLDER;
			this.caDirectory = esgHome + File.separator + CA_DIRECTORY;
		}
	}

	/**
	 * Retrieve credentials from ESGF IdP node and write all requested files in
	 * the configurated directories.
	 * 
	 * @return {@link ESGFCredentials}
	 * 
	 * @throws Exception
	 * 
	 * @throws IllegalStateException
	 *             if user openID hasn't configured
	 * 
	 */
	public ESGFCredentials retrieveCredentials() throws Exception {
		LOG.trace("[IN]  retrieveCredentials");

		if (openID == null) {
			LOG.error("IllegalStateException. User openID hasn't configured");
			throw new IllegalStateException("User openID hasn't configured");
		}

		// If credentials directory doesn't exist then create new
		File esgDirectory = new File(esgHome);
		if (!esgDirectory.exists()) {
			esgDirectory.mkdir();
			esgDirectory.setExecutable(true);
			esgDirectory.setReadable(true);
			esgDirectory.setWritable(true);
			LOG.debug(".esg is created");
		}

		LOG.debug("Getting CA's certificates from {}...", ESGF_CA_CERTS_URL);
		getCASCertificates();

		LOG.debug("Getting openID info...");
		MyProxyParameters myProxyParams = getMyProxyParametersFromOpenID();
		MyProxyProvider provider = getMyProxyProvider();
		try {
			this.esgfCredentials = provider.getESGFCredentials(bootstrap,
					myProxyParams, this.caDirectory);

			LOG.debug("Writting requested files..");
			writeRequestedFilesFromESGFCredentials(esgfCredentials);

			if (!writeTrustRootsCerts) { // if CAdirectory must not been written
				File caDirectory = new File(this.caDirectory);
				if (caDirectory.exists()) {
					// if exists CAdirectory delete it and its content
					deleteFolder(caDirectory);
				}
			}

		} catch (GeneralSecurityException e) {
			LOG.error("Error in retrieve credentials:{} " + e.getMessage());
			esgfCredentials = null;
			throw e;
		} catch (IOException e) {
			LOG.error("Error in retrieve credentials:{} " + e.getMessage());
			esgfCredentials = null;
			throw e;
		}

		LOG.trace("[OUT] retrieveCredentials");
		return esgfCredentials;

	}

	/**
	 * Private method. Write the requested files in file system.
	 */
	private void writeRequestedFilesFromESGFCredentials(
			ESGFCredentials esgfCredentials) throws IllegalStateException,
			IOException, GeneralSecurityException {

		FileOutputStream ous;
		String path;

		if (writePem) {
			path = esgHome + File.separator + CREDENTIALS_FILE_PEM;
			ous = new FileOutputStream(new File(path));
			PemUtil.writeCredentials(ous,
					esgfCredentials.getAllx509Certificates(),
					esgfCredentials.getPrivateKey());
			LOG.info("Pem file has been written in {}", path);
		}
		if (writeJKSKeystore) {
			path = esgHome + File.separator + KEYSTORE_JKS_FILE;
			ous = new FileOutputStream(new File(path));
			KeyStore jksKeyStore = StoreUtil.generateJKSKeystore(
					esgfCredentials.getX509userCertificate(),
					esgfCredentials.getPrivateKey(),
					esgfCredentials.getX509ServerCertificates(),
					KEYSTORE_PASSWORD);
			jksKeyStore.store(ous, KEYSTORE_PASSWORD.toCharArray());
			LOG.info("JKS keystore has been written in {}", path);
		}
		if (writeJCEKSKeystore) {
			path = esgHome + File.separator + KEYSTORE_JCEKS_FILE;
			ous = new FileOutputStream(new File(path));
			KeyStore jceksKeyStore = StoreUtil.generateJCEKSKeystore(
					esgfCredentials.getX509userCertificate(),
					esgfCredentials.getPrivateKey(),
					esgfCredentials.getX509ServerCertificates(),
					KEYSTORE_PASSWORD);
			jceksKeyStore.store(ous, KEYSTORE_PASSWORD.toCharArray());
			LOG.info("JCEKS keystore has been written in {}", path);
		}
		if (writeCaCertsPem) {
			path = esgHome + File.separator + CAS_CERTIFICATES_PEM;
			ous = new FileOutputStream(new File(path));
			PemUtil.writeCACertificate(new FileOutputStream(path),
					getCaDirectoryPath());
			LOG.info("Ca's certificates in pem format have been written in {}",
					path);
		}

	}

	/**
	 * Get the MyProxyLibrary configurate
	 * 
	 * @return the myProxyLib
	 */
	public Lib getMyProxyLib() {
		return myProxyLib;
	}

	/**
	 * Set the MyProxy library
	 * 
	 * @param myProxyLib
	 *            the myProxyLib to set
	 */
	public void setMyProxyLib(Lib myProxyLib) {
		this.myProxyLib = myProxyLib;
	}

	/**
	 * Retrieve ESGF truststore
	 * 
	 * @return
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	public KeyStore retrieveESGFTrustStore() throws GeneralSecurityException,
			IOException {
		URL trustURL = new URL(FEDERATION_TRUSTSTORE_URL);
		KeyStore truststore = StoreUtil.loadJKSTrustStore(
				trustURL.openStream(), KEYSTORE_PASSWORD);
		if (writeTruststore) {
			// Save truststore in system file
			truststore.store(new BufferedOutputStream(new FileOutputStream(
					new File(esgHome + File.separator + TRUSTSTORE_FILE))),
					KEYSTORE_PASSWORD.toCharArray());
		}
		return truststore;
	}

	/**
	 * Set the directory where the credentials will be retrieved
	 * 
	 * @param esgHome
	 *            the path of directory
	 */
	public void setCredentialsDirectory(String directory) {
		this.esgHome = directory;
		this.caDirectory = esgHome + File.separator + CA_DIRECTORY;
	}

	/**
	 * Sets if trustroots certificates will be written in a pem format
	 * 
	 * @param flag
	 */
	public void setWriteCaCertsPem(boolean flag) {
		this.writeCaCertsPem = flag;
	}

	/**
	 * Sets if credentials will be written in JCEKS keystore.
	 * 
	 * @param flag
	 */
	public void setWriteJCEKSKeystore(boolean flag) {
		this.writeJCEKSKeystore = flag;
	}

	/**
	 * Sets if credentials will be written in JKS keystore.
	 * 
	 * @param flag
	 */
	public void setWriteJKSKeystore(boolean flag) {
		this.writeJKSKeystore = flag;
	}

	/**
	 * Sets if credentials will be written in a pem format.
	 * 
	 * @param flag
	 */
	public void setWritePem(boolean flag) {
		this.writePem = flag;
	}

	/**
	 * Sets if trustroots certificates will be written in a folder.
	 * 
	 * @param flag
	 */
	public void setWriteTrustRootsCerts(boolean flag) {
		this.writeTrustRootsCerts = flag;
	}

	/**
	 * Set if truststore of CA roots certs will be written in a file
	 * (esgf-trustore.ts).
	 * 
	 * @param flag
	 */
	public void setWriteTruststore(boolean flag) {
		this.writeTruststore = flag;
	}

	/**
	 * Get MyProxy parameters to retrieve ESGF credentials by OpenID
	 * 
	 * @return
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	private MyProxyParameters getMyProxyParametersFromOpenID()
			throws IOException, GeneralSecurityException {

		LOG.debug("Getting connection with OpenID");
		String openIdURLStr = openID.getUserName(); // get OpenID URL
		URL url = new URL(openIdURLStr);
		InputStream localInputStream = null;

		try {
			HttpURLConnection openIdConnection = getSecureConnection(openIdURLStr);
			openIdConnection.connect();
			// read openId XML document
			localInputStream = openIdConnection.getInputStream();
		} catch (SSLHandshakeException e) {
			LOG.warn("SSLHandshakeException, removing SSLv3 and SSLv2Hello protocols");
			try {

				SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory
						.getDefault();
				SSLSocket sslSocket = (SSLSocket) sslSocketFactory
						.createSocket(url.getHost(), 443);

				// Strip "SSLv3" from the current enabled protocols.
				String[] protocols = sslSocket.getEnabledProtocols();
				Set<String> set = new HashSet<String>();
				for (String s : protocols) {
					if (s.equals("SSLv3") || s.equals("SSLv2Hello")) {
						continue;
					}
					set.add(s);
				}
				sslSocket.setEnabledProtocols(set.toArray(new String[0]));

				// get openID xml
				PrintWriter out = new PrintWriter(new OutputStreamWriter(
						sslSocket.getOutputStream()));
				out.println("GET " + url.toString() + " HTTP/1.1");
				out.println();
				out.flush();

				// read openid url content
				InputStream in = sslSocket.getInputStream();
				final BufferedReader reader = new BufferedReader(
						new InputStreamReader(in));

				// read headers
				boolean head = true;
				int headLen = 0;
				int contentLen = 0;
				String line = null;
				line = reader.readLine();

				while (head == true & line != null) {
					if (head) {
						headLen = headLen + line.length();
						if (line.trim().equals("")) {
							head = false;
						} else {
							String[] headers = line.trim().split(" ");
							if (headers[0].equals("Content-Length:")) {
								contentLen = Integer.parseInt(headers[1]);
							}
							line = reader.readLine();
						}
					}
				}

				// read content
				char[] buffContent = new char[contentLen];
				reader.read(buffContent);
				reader.close();

				// make inpuStream for the content
				String content = new String(buffContent);
				localInputStream = new ByteArrayInputStream(content.getBytes());

			} catch (Exception e1) {
				System.err.println("Can't parse OpenID: " + e.getMessage());
			}
		}

		Document localDocument;
		try {
			if (localInputStream == null) {
				throw new IOException("OpenID couldn't be read. Null value");
			}
			localDocument = DocumentBuilderFactory.newInstance()
					.newDocumentBuilder().parse(localInputStream);

			// Get myproxy-service info
			DOMSource domSource = new DOMSource(localDocument);
			StringWriter writer = new StringWriter();
			StreamResult result = new StreamResult(writer);
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer transformer = tf.newTransformer();
			transformer.transform(domSource, result);
			LOG.debug("OpenID XML: \n" + writer.toString());

			LOG.debug("Getting my proxy service from OpenId XML");
			// Get myproxy-service section in xml
			XPath localXPath = XPathFactory.newInstance().newXPath();
			XPathExpression localXPathExpression = localXPath
					.compile("//*[Type='urn:esg:security:myproxy-service']/URI");
			String str = (String) localXPathExpression.evaluate(localDocument,
					XPathConstants.STRING);
			String[] arrayOfString = str.split(":");

			// my proxy params
			String userName = (openIdURLStr.substring(openIdURLStr
					.lastIndexOf("/") + 1));
			String password = String.valueOf(openID.getPassword());
			String host = (arrayOfString[1].substring(2));
			int port = (Integer.parseInt(arrayOfString[2]));
			int lifetime = LIFE_TIME;

			return new MyProxyParameters(userName, password, host, port,
					lifetime, this.writeTrustRootsCerts);

		} catch (SAXException e) {
			throw new IOException(e.getMessage(), e.getCause());
		} catch (ParserConfigurationException e) {
			throw new IOException(e.getMessage(), e.getCause());
		} catch (TransformerConfigurationException e) {
			throw new IOException(e.getMessage(), e.getCause());
		} catch (TransformerException e) {
			throw new IOException(e.getMessage(), e.getCause());
		} catch (XPathExpressionException e) {
			throw new IOException(e.getMessage(), e.getCause());
		}

	}

	/**
	 * Get secure connection {@link HttpURLConnection} to openIdUrl with
	 * permissions (truststore)
	 * 
	 * @param openIdURLStr
	 *            openID url
	 * @return
	 * @throws IOException
	 *             , GeneralSecurityException
	 * @throws Exception
	 *             any error
	 */
	private HttpsURLConnection getSecureConnection(String openIdURLStr)
			throws IOException, GeneralSecurityException {

		LOG.trace("[IN]  getSecureConnection");

		SSLContext context = null;
		HttpsURLConnection secureConnection = null;

		LOG.debug("Creating new httpsUrlConnection to access openId info");
		// New HttpsURLConnection
		URL secureUrl = new URL(openIdURLStr);
		URLConnection sslConnection = secureUrl.openConnection();
		secureConnection = (HttpsURLConnection) sslConnection;

		LOG.debug("Generating truststore factory...");
		KeyStore truststore = retrieveESGFTrustStore();
		TrustManagerFactory tmf = TrustManagerFactory
				.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(truststore);

		LOG.debug("Generating SSL context with truststore factory...");
		context = SSLContext.getInstance(SSLCONTEXT);
		context.init(null, tmf.getTrustManagers(), null);
		secureConnection.setSSLSocketFactory(context.getSocketFactory());
		LOG.debug("Secure openIdConnection (with ssl context) is generated");

		LOG.trace("[OUT] getSecureConnection");
		return secureConnection;
	}

	/**
	 * Set a MyproxyProvider
	 * 
	 * @return
	 */
	private MyProxyProvider getMyProxyProvider() {
		if (this.myProxyLib == Lib.MYPROXYLOGON) {
			return new MyProxyLogonProvider();
		} else {
			return new MyProxy206Provider();
		}
	}

	/**
	 * Retrieve CA's from ESGF URL. If fails try use the CA's in caDirectory if
	 * this directory exists and isn't empty
	 * 
	 * @throws IOException
	 *             If CA's can't be retrieved from ESGF. If the retrieval fails
	 *             this exception is raised when CA's can' be loaded from
	 *             caDirectory because CA's directory is empty or isn't exists"
	 * @throws ArchiveException
	 *             If CA's retrieved can't be write in file system
	 */
	private void getCASCertificates() throws IOException, ArchiveException {

		boolean caRetrieved = false;
		InputStream is = null;

		try {
			URL url = new URL(ESGF_CA_CERTS_URL);
			URLConnection connection;
			connection = url.openConnection();
			is = connection.getInputStream();
			caRetrieved = true;
		} catch (IOException e) {
			LOG.warn("CA's certificates can't be retrieved");
		}

		// if is success
		if (caRetrieved) {
			try {
				writeCAsCertificates(is);
			} catch (IOException e) {
				throw e;
			} catch (ArchiveException e) {
				throw e;
			}
		} else { // if CA's can't be retrieved check if exists CA's
					// previously download in caDirectory
			File caDirectory = new File(this.caDirectory);
			if (!caDirectory.exists() | !caDirectory.isDirectory()) {
				LOG.error("CA's can't be retrieved from {} and can't"
						+ " be loaded from {} in file system",
						ESGF_CA_CERTS_URL, caDirectory);
				throw new IOException("CA's can't be retrieved from "
						+ ESGF_CA_CERTS_URL + " and can't be loaded from"
						+ caDirectory + " in file system");
			}

			if (caDirectory.listFiles().length < 1) {
				LOG.error("CA's can't be retrieved from {} and can't"
						+ " be loaded from {} in file system"
						+ " because CA's directory is empty",
						ESGF_CA_CERTS_URL, caDirectory);
				throw new IOException("CA's can't be retrieved from "
						+ ESGF_CA_CERTS_URL + " and can't be loaded from"
						+ caDirectory + " in file system because CA's"
						+ " directory is empty");
			}
		}
	}

	private void writeCAsCertificates(InputStream in) throws IOException,
			ArchiveException {
		// read tar from ESGF URL
		String tempPath = System.getProperty("java.io.tmpdir") + File.separator
				+ "esg-certificates.tar";
		File tarFile = new File(tempPath);

		// untar certificates
		String dir = System.getProperty("java.io.tmpdir") + File.separator;
		File tempCertDir = new File(dir);

		List<File> certs = unTar(tarFile, tempCertDir);

		// Copy untar certs in $ESG_HOME/certificates
		File caDirectory = new File(this.caDirectory);
		if (!caDirectory.exists()) {
			caDirectory.mkdir();
		} else {
			// if exists CAdirectory delete it and its content
			deleteFolder(caDirectory);
			caDirectory.mkdir(); // create new directory
		}
		caDirectory.deleteOnExit();

		for (File cert : certs) {
			if (!cert.isDirectory()) {
				if (cert.getCanonicalPath() == cert.getAbsolutePath()) {
					File outputFile = new File(caDirectory, cert.getName());
					final OutputStream outputFileStream = new FileOutputStream(
							outputFile);
					IOUtils.copy(new FileInputStream(cert),
							new FileOutputStream(outputFile));
					outputFileStream.close();
				} else { // symlink

					String symlink = cert.getCanonicalPath();
					File linkDest = new File(symlink);

					File outputFile = new File(caDirectory, cert.getName());
					final OutputStream outputFileStream = new FileOutputStream(
							outputFile);
					IOUtils.copy(new FileInputStream(linkDest),
							new FileOutputStream(outputFile));
					outputFileStream.close();

				}
			}
		}
	}

	/**
	 * Delete folder and its content
	 */
	private void deleteFolder(File folder) {
		File[] files = folder.listFiles();
		if (files != null) { // some JVMs return null for empty dirs
			for (File f : files) {
				if (f.isDirectory()) {
					deleteFolder(f);
				} else {
					f.delete();
				}
			}
		}
		folder.delete();
	}

	/**
	 * Untar an input file into an output file. The output file is created in
	 * the output folder, having the same name as the input file, minus the
	 * '.tar' extension.
	 * 
	 * @param inputFile
	 *            the input .tar file
	 * @param outputDir
	 *            the output directory file.
	 * @throws IOException
	 * @throws FileNotFoundException
	 * 
	 * @return The {@link List} of {@link File}s with the untared content.
	 * @throws ArchiveException
	 */
	private static List<File> unTar(final File inputFile, final File outputDir)
			throws FileNotFoundException, IOException, ArchiveException {

		LOG.debug(String.format("Untaring %s to dir %s.",
				inputFile.getAbsolutePath(), outputDir.getAbsolutePath()));

		final List<File> untaredFiles = new LinkedList<File>();
		final InputStream is = new FileInputStream(inputFile);
		final TarArchiveInputStream debInputStream = (TarArchiveInputStream) new ArchiveStreamFactory()
				.createArchiveInputStream("tar", is);
		TarArchiveEntry entry = null;
		while ((entry = (TarArchiveEntry) debInputStream.getNextEntry()) != null) {
			final File outputFile = new File(outputDir, entry.getName());

			if (entry.isDirectory()) {
				LOG.debug(String.format(
						"Attempting to write output directory %s.",
						outputFile.getAbsolutePath()));
				if (!outputFile.exists()) {
					LOG.info(String.format(
							"Attempting to create output directory %s.",
							outputFile.getAbsolutePath()));
					if (!outputFile.mkdirs()) {
						throw new IllegalStateException(String.format(
								"Couldn't create directory %s.",
								outputFile.getAbsolutePath()));
					}
				}
			} else {
				LOG.debug(String.format("Creating output file %s.",
						outputFile.getAbsolutePath()));
				final OutputStream outputFileStream = new FileOutputStream(
						outputFile);

				if (entry.isSymbolicLink()) {
					String symLinkFileName = entry.getLinkName();

					IOUtils.copy(
							new FileInputStream(new File(outputFile.getParent()
									+ File.separator + symLinkFileName)),
							outputFileStream);
					outputFileStream.close();

				} else {
					IOUtils.copy(debInputStream, outputFileStream);
					outputFileStream.close();
				}
			}
			untaredFiles.add(outputFile);
		}
		debInputStream.close();

		return untaredFiles;
	}
}
