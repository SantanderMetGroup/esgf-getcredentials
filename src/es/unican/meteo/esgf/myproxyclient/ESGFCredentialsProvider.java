/**
 * 
 */
package es.unican.meteo.esgf.myproxyclient;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.PasswordAuthentication;
import java.net.URL;
import java.net.URLConnection;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
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
 * Singleton class.
 * 
 * @author Karem Terry
 */
public class ESGFCredentialsProvider {
	
	 /** Logger. */
    static private org.slf4j.Logger logger = org.slf4j.LoggerFactory
            .getLogger(ESGFCredentialsProvider.class);

    // Constants.
    private static final String FEDERATION_TRUSTSTORE_URL = "https://raw.github.com/ESGF/esgf-dist/master/installer/certs/esg-truststore.ts";
    private static final String ESGF_CA_CERTS_URL="https://raw.githubusercontent.com/ESGF/esgf-dist/master/installer/certs/esg_trusted_certificates.tar";
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
	private static final String CAS_CERTIFICATES_PEM ="ca-certificates.pem";
	
	public enum Lib{/**myproxy-logon 1.4.6*/MYPROXYLOGON, /**myproxy 2.0.6.*/MYPROXYV206;}

    /** Path user's folder for ESG credentials. */
    private static String esgHome;
	/** Path of folder of caDirectory.*/
    private String caDirectory;
    /** State of Credentials Manager (Inititialized or not). */
    private boolean initialized;
    /** Singleton instance. */
    private static ESGFCredentialsProvider INSTANCE = null;
    /** OpenID account. */
    private PasswordAuthentication openID;
    /** ESGF Credentials.*/
    private ESGFCredentials esgfCredentials;
    /** Boolean that indicates if write certificates in .pem format.*/
    private boolean writePem;
    /** Boolean that indicates if write JKS keystore file.*/
    private boolean writeJKSKeystore;
    /** Boolean that indicates if write JCEKS keystore file.*/
    private boolean writeJCEKSKeystore;
	/** Boolean that indicates if write certificates trustroots directory.*/
    private boolean writeTrustRootsCerts;
	/** Boolean that indicates if write esgf trustore.*/
	private boolean writeTruststore;
	/** Boolean that indicates if write esgf trustore.*/
	private boolean writeCaCertsPem;
	/** Library of MyProxyProvider.*/
	private Lib myProxyLib;

    
	/**
     * Create a thread-safe singleton.
     */
    private static void createInstance() {
        logger.trace("[IN]  createInstance");

        logger.debug("Checking if exist an instance of ESGFCredentialsProvider");
        // creating a thread-safe singleton
        if (INSTANCE == null) {

            // Only the synchronized block is accessed when the instance hasn't
            // been created.
            synchronized (ESGFCredentialsProvider.class) {
                // Inside the block it must check again that the instance has
                // not been created.
                if (INSTANCE == null) {
                    logger.debug("Creating new instance of ESGFCredentialsProvider");
                    INSTANCE = new ESGFCredentialsProvider();
                }
            }
        }
        logger.trace("[OUT] createInstance");
    }
    
    /**
     * Get singleton instance of {@link ESGFCredentialsProvider}. This instance is
     * the only that exists.
     * 
     * @return the unique instance of {@link ESGFCredentialsProviders}.
     */
    public static ESGFCredentialsProvider getInstance() {
        logger.trace("[IN]  getInstance");
        createInstance();
        logger.trace("[OUT] getInstance");
        return INSTANCE;
    }
    
    
    /**
     * Constructor. Creates the ESGF credentials provider. If the user has a ESG_HOME
     * environment variable set, then it is used as the folder to store the ESG
     * credentials; otherwise, the default folder (&lt;user home
     * folder&gt;/.esg) is used.
     */
    private ESGFCredentialsProvider() {
        logger.trace("[IN]  ESGFCredentialsProvider");
        // use ESG_HOME environmental variable if exists
        Map<String, String> env = System.getenv();
        if (env.containsKey(ESG_HOME_ENV_VAR)) {
            this.esgHome = env.get(ESG_HOME_ENV_VAR);
            this.caDirectory=esgHome+ File.separator +CA_DIRECTORY;
        } else { // use default directory if not
            String homePath = System.getProperty("user.home");
            this.esgHome = homePath + File.separator + DEFAULT_ESG_FOLDER;
            this.caDirectory=esgHome+ File.separator +CA_DIRECTORY;
        }
        
        openID = null;
        esgfCredentials=null;
        myProxyLib=Lib.MYPROXYLOGON;//default lib for myproxy

        logger.trace("[OUT] ESGFCredentialsProvider");
    }
    
    
    /**
     * Get the directory where the credentials will be retrieved
	 * @return directory where the credentials will be retrieved
	 */
	public String getCredentialsDirectory() {
		return esgHome;
	}

	
    /**
     * Check if ESgf Credentials Provider has been initiated.
     * 
     * @return true if is configured and otherwise false.
     */
    public synchronized boolean hasInitiated() {
        logger.trace("[IN]  hasInitiated");
        logger.trace("[OUT] hasInitiated");
        return initialized;
    }


	/**
     * Initialize ESGF credentials provider with an openID. If previously
     * has been initiated then reset all state of credential manager and
     * reinitialize it.
     * 
     * @param openIDURL
     *            OpenID-enabled URL that can be used to log into OpenID-enabled
     *            websites
     * @param password
     *            OpenID password
     * @return MessageError String if connection failed or null is success
     * @throws IOException
     *             if some error happens getting credentials
     */
    public synchronized void initialize(String openIDURL, char[] password)
    		throws IOException {
    	logger.trace("[IN]  initialize");
    	
    	esgfCredentials=null;
    	openID = new PasswordAuthentication(openIDURL, password);
    	initialized = true;

    	logger.trace("[OUT] initialize");
    }
	
	
    /**
     * Gets directory of trust roots certs.
	 * @return the caDirectory
	 */
	public String getCaDirectoryPath() {
		return caDirectory;
	}

	/**
	 * Sets folder name of trust roots certs.
	 * @param caDirectory theory path direct
	 */
	public void setCaDirectoryName(String folderName) {
		this.caDirectory = esgHome+ File.separator +folderName;
	}

	/**
	 * Return true if trustroots certificates will be written in a pem format.
	 * @return the writeCaCertsPem
	 */
	public boolean isWriteCaCertsPem() {
		return writeCaCertsPem;
	}


	/**
	 * Return true if credentials will be written in JCEKS keystore.
	 * @return the writeJCEKSKeystore
	 */
	public boolean isWriteJCEKSKeystore() {
		return writeJCEKSKeystore;
	}


	/**
	 * Return true if credentials will be written in JKS keystore.
	 * @return the writeJKSKeystore
	 */
	public boolean isWriteJKSKeystore() {
		return writeJKSKeystore;
	}


	/**
     * Return true if credentials will be written in a pem format.
	 * @return the writePem
	 */
	public boolean isWritePem() {
		return writePem;
	}


	/**
	 * Return true if trustroots certificates will be written in a directory.
	 * @param requestTrustRoots the requestTrustRoots to set
	 */
	public boolean isWriteTrustRootsCerts() {
		return writeTrustRootsCerts;
	}


	/**
     * Return true if truststore will be written in a file.
	 * @return the writeTruststore
	 */
	public boolean isWriteTruststore() {
		return writeTruststore;
	}


	/**
	 * Reset credentials directory to the value of ESG_HOME environment variable if is set; 
	 * otherwise, the default folder (&lt;user home folder&gt;/.esg) is used.
	 * 
	 */
	public void resetCredentialsDirectory() {
		// use ESG_HOME environmental variable if exists
        Map<String, String> env = System.getenv();
        
        if (env.containsKey(ESG_HOME_ENV_VAR)) {
            this.esgHome = env.get(ESG_HOME_ENV_VAR);
            this.caDirectory=esgHome+ File.separator +CA_DIRECTORY;
        } else { // use default directory if not
            String homePath = System.getProperty("user.home");
            this.esgHome = homePath + File.separator + DEFAULT_ESG_FOLDER;
            this.caDirectory=esgHome+ File.separator +CA_DIRECTORY;
        }
	}


	/**
     * Get credentials from ESGF IdP node.
     * 
     * @throws Exception
     * 
     * @throws IllegalStateException
     *             if user openID hasn't configured
     */
    public void retrieveCredentials() throws Exception {
    	logger.trace("[IN]  retrieveCredentials");


    	if (openID == null) {
    		logger.error("IllegalStateException. User openID hasn't configured");
    		throw new IllegalStateException("User openID hasn't configured");
    	}

    	// If credentials directory doesn't exist then create new
    	File esgDirectory = new File(esgHome);
    	if (!esgDirectory.exists()) {
    		esgDirectory.mkdir();
    		esgDirectory.setExecutable(true);
    		esgDirectory.setReadable(true);
    		esgDirectory.setWritable(true);
    		logger.debug(".esg is created");
    	}
    	
    	logger.debug("Getting CA's certificates from {}...", ESGF_CA_CERTS_URL);
    	getCASCertificates();
    	
    	logger.debug("Getting openID info...");
    	MyProxyParameters myProxyParams= getMyProxyParametersFromOpenID();
    	MyProxyProvider provider= getMyProxyProvider();
    	try{
    		this.esgfCredentials=provider.getESGFCredentials(myProxyParams, this.caDirectory);

    		FileOutputStream ous;
    		String path;
    		
    		logger.debug("Writting requested files..");
    		if(writePem){
    			path=esgHome+ File.separator + CREDENTIALS_FILE_PEM;
    			ous= new FileOutputStream(new File(path));
    			PemUtil.writeCredentials(ous, esgfCredentials.getAllx509Certificates(), esgfCredentials.getPrivateKey());
    			logger.info("Pem file has been written in {}", path);
    		}
    		if(writeJKSKeystore){
    			path=esgHome+ File.separator + KEYSTORE_JKS_FILE;
    			ous= new FileOutputStream(new File(path));
    			KeyStore jksKeyStore=
    					StoreUtil.generateJKSKeystore(esgfCredentials.getX509userCertificate(), 
    							esgfCredentials.getPrivateKey(), 
    							esgfCredentials.getX509ServerCertificates(), KEYSTORE_PASSWORD);		
    			jksKeyStore.store(ous, KEYSTORE_PASSWORD.toCharArray());
    			logger.info("JKS keystore has been written in {}", path);
    		}
    		if(writeJCEKSKeystore){
    			path=esgHome+ File.separator + KEYSTORE_JCEKS_FILE;
    			ous= new FileOutputStream(new File(path));
    			KeyStore jceksKeyStore=
    					StoreUtil.generateJCEKSKeystore(esgfCredentials.getX509userCertificate(), 
    							esgfCredentials.getPrivateKey(), 
    							esgfCredentials.getX509ServerCertificates(), KEYSTORE_PASSWORD);		
    			jceksKeyStore.store(ous, KEYSTORE_PASSWORD.toCharArray());
    			logger.info("JCEKS keystore has been written in {}", path);
    		}
    		if(writeCaCertsPem){
    			path=esgHome+ File.separator + CAS_CERTIFICATES_PEM;
    			ous= new FileOutputStream(new File(path));
    			PemUtil.writeCACertificate(new FileOutputStream(path), getCaDirectoryPath());
    			logger.info("Ca's certificates in pem format have been written in {}", path);
    		}

    	} catch (GeneralSecurityException e) {
    		logger.error("Error in retrieve credentials:{} "
    				+ e.getMessage());
    		esgfCredentials=null;
    		throw e;
    	} catch (IOException e) {
    		logger.error("Error in retrieve credentials:{} "
    				+ e.getMessage());
    		esgfCredentials=null;
    		throw e;
    	}

    	logger.trace("[OUT] retrieveCredentials");
    }
    

	/**
	 * Get the MyProxyLibrary configurate
	 * @return the myProxyLib
	 */
	public Lib getMyProxyLib() {
		return myProxyLib;
	}

	/**
	 * Set the MyProxy library
	 * @param myProxyLib the myProxyLib to set
	 */
	public void setMyProxyLib(Lib myProxyLib) {
		this.myProxyLib = myProxyLib;
	}

	/**
     * Retrieve ESGF truststore
     * @return
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public KeyStore retrieveESGFTrustStore() throws GeneralSecurityException, IOException{
    	URL trustURL = new URL(FEDERATION_TRUSTSTORE_URL);
        KeyStore truststore=StoreUtil.loadJKSTrustStore(trustURL.openStream(), KEYSTORE_PASSWORD);
    	if(writeTruststore){
    		// Save truststore in system file
    		truststore.store(
    				new BufferedOutputStream(new FileOutputStream(new File(
    						esgHome + File.separator + TRUSTSTORE_FILE))),
    						KEYSTORE_PASSWORD.toCharArray());
    	}
    	return truststore;
    }


	/**
	 * Set the directory where the credentials will be retrieved
	 * @param esgHome the path of directory
	 */
	public void setCredentialsDirectory(String directory) {
		this.esgHome = directory;
		this.caDirectory=esgHome+ File.separator +CA_DIRECTORY;
	}


	/**
	 * Sets if trustroots certificates will be written in a pem format
	 * @param flag
	 */
	public void setWriteCaCertsPem(boolean flag) {
		this.writeCaCertsPem = flag;
	}
   

    /**
	 * Sets if credentials will be written in JCEKS keystore.
	 * @param flag
	 */
	public void setWriteJCEKSKeystore(boolean flag) {
		this.writeJCEKSKeystore = flag;
	}

    
    /**
	 * Sets if credentials will be written in JKS keystore.
	 * @param flag 
	 */
	public void setWriteJKSKeystore(boolean flag) {
		this.writeJKSKeystore = flag;
	}


    /**
	 * Sets if credentials will be written in a pem format.
	 * @param flag
	 */
	public void setWritePem(boolean flag) {
		this.writePem = flag;
	}


    /**
	 * Sets if trustroots certificates will be written in a directory.
	 * @param flag
	 */
	public void setWriteTrustRootsCerts(boolean flag) {
		this.writeTrustRootsCerts = flag;
	}


    /**
	 * Set if truststore will be written in a file.
	 * @param flag
	 */
	public void setWriteTruststore(boolean flag) {
		this.writeTruststore = flag;
	}
	
	/**
	 * Get MyProxy parameters to retrieve ESGF credentials by OpenID
	 * @return
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	private MyProxyParameters getMyProxyParametersFromOpenID() throws IOException, GeneralSecurityException {

    	logger.debug("Getting connection with OpenID");
    	String openIdURLStr = openID.getUserName();
    	HttpURLConnection openIdConnection = getSecureConnection(openIdURLStr);
    	openIdConnection.connect();


    	// read openId XML document
    	InputStream localInputStream = openIdConnection.getInputStream();

    	Document localDocument;
    	try {
    		localDocument = DocumentBuilderFactory.newInstance()
    				.newDocumentBuilder().parse(localInputStream);

    		// Get myproxy-service info
    		DOMSource domSource = new DOMSource(localDocument);
    		StringWriter writer = new StringWriter();
    		StreamResult result = new StreamResult(writer);
    		TransformerFactory tf = TransformerFactory.newInstance();
    		Transformer transformer = tf.newTransformer();
    		transformer.transform(domSource, result);
    		logger.debug("OpenID XML: \n" + writer.toString());

    		logger.debug("Getting my proxy service from OpenId XML");
    		// Get myproxy-service section in xml
    		XPath localXPath = XPathFactory.newInstance().newXPath();
    		XPathExpression localXPathExpression = localXPath
    				.compile("//*[Type='urn:esg:security:myproxy-service']/URI");
    		String str = (String) localXPathExpression.evaluate(localDocument,
    				XPathConstants.STRING);
    		String[] arrayOfString = str.split(":");

    		//my proxy params
    		String userName = (openIdURLStr
    				.substring(openIdURLStr.lastIndexOf("/") + 1));
    		String password=String.valueOf(openID.getPassword());
    		String host = (arrayOfString[1].substring(2));
    		int port = (Integer.parseInt(arrayOfString[2]));
    		int lifetime=LIFE_TIME;


    		return new MyProxyParameters(userName, password, host, port, lifetime, this.writeTrustRootsCerts);

    	} catch (SAXException e) {
    		throw new IOException(e.getMessage(),e.getCause());
    	} catch (ParserConfigurationException e) {
    		throw new IOException(e.getMessage(),e.getCause());
    	} catch (TransformerConfigurationException e) {
    		throw new IOException(e.getMessage(),e.getCause());
    	} catch (TransformerException e) {
    		throw new IOException(e.getMessage(),e.getCause());
    	} catch (XPathExpressionException e) {
    		throw new IOException(e.getMessage(),e.getCause());
    	}

    }


	/**
     * Get secure connection {@link HttpURLConnection} to openIdUrl with
     * permissions (truststore)
     * 
     * @param openIdURLStr
     *            openID url
     * @return
     * @throws IOException, GeneralSecurityException 
     * @throws Exception
     *             any error
     */
    private HttpsURLConnection getSecureConnection(String openIdURLStr) throws IOException, GeneralSecurityException  {

    	logger.trace("[IN]  getSecureConnection");

    	SSLContext context = null;
    	HttpsURLConnection secureConnection = null;

    	logger.debug("Creating new httpsUrlConnection to access openId info");
    	// New HttpsURLConnection
    	URL secureUrl = new URL(openIdURLStr);
    	URLConnection sslConnection = secureUrl.openConnection();
    	secureConnection = (HttpsURLConnection) sslConnection;


    	logger.debug("Generating truststore factory...");
    	KeyStore truststore=retrieveESGFTrustStore();
    	TrustManagerFactory tmf = TrustManagerFactory
    			.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    	tmf.init(truststore);

    	logger.debug("Generating SSL context with truststore factory...");
    	context = SSLContext.getInstance(SSLCONTEXT);
    	context.init(null, tmf.getTrustManagers(), null);
    	secureConnection.setSSLSocketFactory(context.getSocketFactory());
    	logger.debug("Secure openIdConnection (with ssl context) is generated");


    	logger.trace("[OUT] getSecureConnection");
    	return secureConnection;
    }
	
	
    /**
     * Set a MyproxyProvider 
     * @return
     */
	private MyProxyProvider getMyProxyProvider() {
		if(this.myProxyLib==Lib.MYPROXYLOGON){
			return new MyProxyLogonProvider();
		}else{
			return new MyProxy206Provider();
		}
	}
	
	private void getCASCertificates() 
			throws IOException, ArchiveException {
		URL url = new URL(ESGF_CA_CERTS_URL);
		URLConnection connection = url.openConnection();
		InputStream is = connection.getInputStream();
		writeCAsCertificates(is);
	}
	
	private void writeCAsCertificates(InputStream in) 
			throws IOException, ArchiveException{
		//read tar from ESGF URL
		String tempPath=System.getProperty("java.io.tmpdir")+ File.separator+"esg-certificates.tar";
		File tarFile=new File(tempPath);
		OutputStream ous=new FileOutputStream(tarFile);
		byte[] buf =new byte[1024];
		int len;
		while((len=in.read(buf))>0){
			ous.write(buf,0,len);
		}
		ous.close();
		in.close();
		
		//untar certificates
		String dir=System.getProperty("java.io.tmpdir")+ File.separator;
		File tempCertDir=new File(dir);
		List<File> certs=unTar(tarFile, tempCertDir);
		
		//Copy untar certs in $ESG_HOME/certificates
		File caDirectory= new File(this.caDirectory);
		if(!caDirectory.exists()){
			caDirectory.mkdir();
		}
		
		for(File cert: certs){
			if(!cert.isDirectory()){
			File outputFile = new File(caDirectory, cert.getName());
			final OutputStream outputFileStream = new FileOutputStream(outputFile); 
			IOUtils.copy(new FileInputStream(cert), new FileOutputStream(outputFile));
            outputFileStream.close();
			}
		}
	}
	
	/** Untar an input file into an output file.
	 * The output file is created in the output folder, having the same name
	 * as the input file, minus the '.tar' extension. 
	 * 
	 * @param inputFile     the input .tar file
	 * @param outputDir     the output directory file. 
	 * @throws IOException 
	 * @throws FileNotFoundException
	 *  
	 * @return  The {@link List} of {@link File}s with the untared content.
	 * @throws ArchiveException 
	 */
	private static List<File> unTar(final File inputFile, final File outputDir) throws FileNotFoundException, IOException, ArchiveException {

	    logger.debug(String.format("Untaring %s to dir %s.", inputFile.getAbsolutePath(), outputDir.getAbsolutePath()));

	    final List<File> untaredFiles = new LinkedList<File>();
	    final InputStream is = new FileInputStream(inputFile); 
	    final TarArchiveInputStream debInputStream = (TarArchiveInputStream) new ArchiveStreamFactory().createArchiveInputStream("tar", is);
	    TarArchiveEntry entry = null; 
	    while ((entry = (TarArchiveEntry)debInputStream.getNextEntry()) != null) {
	        final File outputFile = new File(outputDir, entry.getName());
	        if (entry.isDirectory()) {
	            logger.debug(String.format("Attempting to write output directory %s.", outputFile.getAbsolutePath()));
	            if (!outputFile.exists()) {
	                logger.info(String.format("Attempting to create output directory %s.", outputFile.getAbsolutePath()));
	                if (!outputFile.mkdirs()) {
	                    throw new IllegalStateException(String.format("Couldn't create directory %s.", outputFile.getAbsolutePath()));
	                }
	            }
	        } else {
	            logger.debug(String.format("Creating output file %s.", outputFile.getAbsolutePath()));
	            final OutputStream outputFileStream = new FileOutputStream(outputFile); 
	            IOUtils.copy(debInputStream, outputFileStream);
	            outputFileStream.close();
	        }
	        untaredFiles.add(outputFile);
	    }
	    debInputStream.close(); 

	    return untaredFiles;
	}
    
}
