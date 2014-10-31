package examples;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;
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

import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import sun.misc.BASE64Encoder;
import MyProxy.MyProxyLogon;

public class RetrieveKeystore {

	public static void main(String args[]) {

		// Constants.
		final String RSA_PRIVATE_KEY_PEM_FOOTER = "-----END RSA PRIVATE KEY-----\n";
		final String RSA_PRIVATE_KEY_PEM_HEADER = "-----BEGIN RSA PRIVATE KEY-----\n";
		final String CERTIFICATE_PEM_FOOTER = "-----END CERTIFICATE-----\n";
		final String CERTIFICATE_PEM_HEADER = "-----BEGIN CERTIFICATE-----\n";
		final String PEM_NAME = "credentials.pem";
		final String KEYSTORE_NAME = "keystore.ks";
		final String PASSWORD = "changeit";
		final String DEFAULT_ESG_FOLDER = ".esg";
		final String ESG_HOME_ENV_VAR = "ESG_HOME";
		final String CERTIFICATES_DIR = "certificates";
		final int LIFE_TIME = 259200;

		String openIdURLStr = "https://esgf-data.dkrz.de/esgf-idp/openid/terryK";
		String passphrase = "unicanMeteo14";
		// String host = "esgf-data.dkrz.de";
		// int port = 7512;

		boolean success = false;
		boolean keyboard = true;

		try {
			if (keyboard) {
				System.out.print("OpenID URL:");
				BufferedReader br = new BufferedReader(new InputStreamReader(
						System.in));

				openIdURLStr = br.readLine();

				System.out.print("Password:");
				br = new BufferedReader(new InputStreamReader(System.in));
				passphrase = br.readLine();
			}
		} catch (IOException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}

		System.out.println("Setting esg home..");
		String esgHome = null;
		// Use ESG_HOME environmental variable if exists
		Map<String, String> env = System.getenv();
		if (env.containsKey(ESG_HOME_ENV_VAR)) {
			esgHome = env.get(ESG_HOME_ENV_VAR);
		} else { // use default directory if not
			String homePath = System.getProperty("user.home");
			esgHome = homePath + File.separator + DEFAULT_ESG_FOLDER;
		}
		System.out.println("..ESG_HOME=" + esgHome);

		// If .esg directory doesn't exist then create new
		File esgDirectory = new File(esgHome);
		if (!esgDirectory.exists()) {
			esgDirectory.mkdir();
			esgDirectory.setExecutable(true);
			esgDirectory.setReadable(true);
			esgDirectory.setWritable(true);
			System.out.println(".esg is created");
		}

		// Get openid values
		try {
			URL url = new URL(openIdURLStr);
			HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
			conn.connect();
			Document localDocument = DocumentBuilderFactory.newInstance()
					.newDocumentBuilder().parse(conn.getInputStream());

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

			String username = (openIdURLStr.substring(openIdURLStr
					.lastIndexOf("/") + 1));

			System.out.println("Generating MyProxyLogon");
			MyProxyLogon mProxyLogon = new MyProxyLogon();

			mProxyLogon.setUsername(username);
			mProxyLogon.setPassphrase(passphrase);
			mProxyLogon.setHost(host);
			mProxyLogon.setPort(port);
			mProxyLogon.setLifetime(LIFE_TIME);
			mProxyLogon.requestTrustRoots(true);

			// Get credentials
			mProxyLogon.getCredentials();
			System.out.println("get credentials success!");

			// Get CA certificates
			mProxyLogon.writeTrustRoots(esgHome + File.separator
					+ CERTIFICATES_DIR);

			// Getting X509Certificate from MyProxyLogon
			Collection<X509Certificate> x509Certificates = mProxyLogon
					.getCertificates();
			Iterator<X509Certificate> iter = x509Certificates.iterator();
			X509Certificate x509Certificate = iter.next();
			System.out.println("X509Certificate has been generated:\n "
					+ x509Certificate);

			// Getting PrivateKey from MyProxyLogon
			PrivateKey key = mProxyLogon.getPrivateKey();
			System.out.println("PrivateKey has been generated:\n "
					+ key.toString());

			// Create keystore: must be type JKS
			KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType()); // JKS
			keystore.load(null);
			keystore.setCertificateEntry("cert-alias", x509Certificate);
			keystore.setKeyEntry("key-alias", key, "changeit".toCharArray(),
					new Certificate[] { x509Certificate });
			System.out.println("Generated keystore in format JKS.");

			System.out.println("Saving keystore in: "
					+ (esgHome + File.separator + KEYSTORE_NAME));
			keystore.store(new BufferedOutputStream(new FileOutputStream(
					new File(esgHome + File.separator + KEYSTORE_NAME))),
					PASSWORD.toCharArray());

			System.out.println("Generating credentials in pem format");
			// Create pem
			FileOutputStream os = new FileOutputStream(esgHome + File.separator
					+ PEM_NAME);
			BASE64Encoder encoder = new BASE64Encoder();

			// Save the certificate
			os.write(CERTIFICATE_PEM_HEADER.getBytes());
			encoder.encodeBuffer(x509Certificate.getEncoded(), os);
			os.write(CERTIFICATE_PEM_FOOTER.getBytes());

			System.out.println("Getting PKCS#1 RSA key from PKCS#8 key...");
			// Save the private key
			byte[] bytes = getPKCS1BytesFromPKCS8Bytes(key.getEncoded());
			String body = encoder.encode(bytes);
			os.write(RSA_PRIVATE_KEY_PEM_HEADER.getBytes());
			os.write(body.getBytes());
			os.write("\n".getBytes());
			os.write(RSA_PRIVATE_KEY_PEM_FOOTER.getBytes());
			os.close();

			System.out.println("PEM has been generated in " + esgHome
					+ File.separator + PEM_NAME);

			success = true;

		} catch (MalformedURLException e) {
			e.printStackTrace();
		} catch (SSLPeerUnverifiedException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (SAXException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ParserConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (XPathExpressionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (TransformerConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (TransformerException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			System.out.println("key store for netcdf isn't generated: " + e);
			e.printStackTrace();
		} catch (Exception e) {
			System.out.println("some error: " + e);
			e.printStackTrace();
		}

		if (success) {
			System.out.println("Success!. Certificates are retrieved.");
		}

	}

	/*
	 * DER format: http://en.wikipedia.org/wiki/Distinguished_Encoding_Rules
	 * PKCS#8: http://tools.ietf.org/html/rfc5208
	 */
	private static byte[] getPKCS1BytesFromPKCS8Bytes(byte[] bytes) {

		byte[] pkcs1Bytes = null;
		int bIndex = 0;

		// Start with PrivateKeyInfo::=SEQUENCE
		// 0x30 Sequence tag
		if (bytes[bIndex] != 0x30) {
			throw new IllegalArgumentException("Not a PKCS#8 private key"); // error
		}

		// next byte contain the number of bytes
		// of SEQUENCE element (length field)
		bIndex = bIndex + 1;

		// Get number of bytes of element
		int sizeOfContent = getSizeOfContent(bytes, bIndex);
		int sizeOfLengthField = getSizeOfLengthField(bytes, bIndex);

		System.out.println("Number of bytes of Sequence:" + sizeOfContent
				+ " Number of bytes of length field:" + sizeOfLengthField);

		// version::=INTEGER
		// shift index to version element
		bIndex = bIndex + sizeOfLengthField;

		// 0x02 Integer tag
		if (bytes[bIndex] != 0x02) {
			throw new IllegalArgumentException("Not a PKCS#8 private key"); // error
		}
		bIndex = bIndex + 1;

		// Get number of bytes of element
		sizeOfContent = getSizeOfContent(bytes, bIndex);
		sizeOfLengthField = getSizeOfLengthField(bytes, bIndex);

		// TODO check version

		System.out.println("Number of bytes of Version:" + sizeOfContent
				+ " Number of bytes of length field:" + sizeOfLengthField);

		// PrivateKeyAlgorithm::= PrivateKeyAlgorithmIdentifier
		// shift index to PrivateKeyAlgorithm element
		bIndex = bIndex + sizeOfLengthField + sizeOfContent;

		// ? PrivateKeyAlgorithmIdentifier tag
		// if (bytes[bIndex] != ?) {
		// throw new IllegalArgumentException("Not a PKCS#8 private key");
		// }
		System.out.println("PrivateKeyAlgorithmIdentifier indentifier octect: "
				+ bytes[bIndex]);
		bIndex = bIndex + 1;

		// Get number of bytes of element
		sizeOfContent = getSizeOfContent(bytes, bIndex);
		sizeOfLengthField = getSizeOfLengthField(bytes, bIndex);

		System.out.println("Number of bytes of PrivateKeyAlgorithm:"
				+ sizeOfContent + " Number of bytes of length field:"
				+ sizeOfLengthField);

		// PrivateKey::= OCTET STRING
		// shift index to PrivateKey element
		bIndex = bIndex + sizeOfLengthField + sizeOfContent;

		// 0x04 OCTET STRING tag
		if (bytes[bIndex] != 0x04) {
			throw new IllegalArgumentException("Not a PKCS#8 private key");
		}
		bIndex = bIndex + 1;

		// Get number of bytes of element
		sizeOfContent = getSizeOfContent(bytes, bIndex);
		sizeOfLengthField = getSizeOfLengthField(bytes, bIndex);

		System.out.println("Number of bytes of PrivateKey:" + sizeOfContent
				+ " Number of bytes of length field:" + sizeOfLengthField);

		return Arrays.copyOfRange(bytes, bIndex + sizeOfLengthField, (bIndex
				+ sizeOfLengthField + sizeOfContent));
	}

	private static int getSizeOfLengthField(byte[] bytes, int bIndex) {
		byte aux = bytes[bIndex];

		if ((aux & 0x80) == 0) { // applies mask
			return 1; // short form
		} else {
			return (aux & 0x7F) + 1; // long form
		}
	}

	/**
	 * Return the number of bytes of element
	 * 
	 * @return
	 */
	private static int getSizeOfContent(byte[] bytes, int bIndex) {

		byte aux = bytes[bIndex];

		if ((aux & 0x80) == 0) { // applies mask
			// short form
			return aux;
		} else {
			// long form
			// if first bit begins with 1 then the rest of bits are the number
			// of bytes that contain the number of bytes of element
			// 375 is 101110111 then in 2 bytes: 00000001 01110111
			// that is the number of bytes that contain the number of bytes
			// ex: 375 is 101110111 then in 2 bytes: 00000001 01110111
			byte numOfBytes = (byte) (aux & 0x7F); // applies mask

			if (numOfBytes * 8 > Integer.SIZE) {
				throw new IllegalArgumentException("ASN.1 field too long");
			}

			int contentLength = 0;

			// find out the number of bits in the bytes
			for (int i = 0; i < numOfBytes; i++) {
				contentLength = (contentLength << 8) + bytes[bIndex + 1 + i];
			}

			return contentLength;
		}

	}
}
