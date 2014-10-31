/**
 * 
 */
package es.unican.meteo.esgf.myproxyclient;

import static org.junit.Assert.fail;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.net.PasswordAuthentication;
import java.net.URL;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @author terryk
 *
 */
public class ESGFCredentialsProviderTest {

	private static final String DKRZ_PASS_AUTH = "/res/dkrz_passAuth";
	private static final String PCMDI_PASS_AUTH = "/res/dkrz_passAuth";

	private static ESGFCredentialsProvider credentialsProvider;
	private static PasswordAuthentication pcmdiAuthentication;
	private static PasswordAuthentication dkrzAuthentication;

	/**
	 * This method is executed once, before the start of all tests.
	 * 
	 * Initialize credentialProvider and read the user-passsword binaries in
	 * /res directory to use in this test. The idea is use the binaries
	 * generated to avoid have to write the user and password each time this
	 * JUnitTest is executed.
	 * 
	 * @throws java.lang.Exception
	 */
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {

		Assert.assertNotNull("Test file missing",
				ESGFCredentialsProviderTest.class.getResource("/test.xml"));

		// init credential provider
		credentialsProvider = credentialsProvider.getInstance();
		String openIdURLStr;
		String passphrase;

		// read user-password binaries or if they don't exists generate them
		// into res directory.
		InputStream inputPCMDI = ESGFCredentialsProviderTest.class
				.getClassLoader().getResourceAsStream(PCMDI_PASS_AUTH);
		InputStream inputDKRZ = ESGFCredentialsProviderTest.class
				.getClassLoader().getResourceAsStream(DKRZ_PASS_AUTH);

		if (inputPCMDI == null) {
			// aks for PCMDI account
			openIdURLStr = "";
			passphrase = "";

			try {

				System.out.print("PCMDI OpenID URL:");
				BufferedReader br = new BufferedReader(new InputStreamReader(
						System.in));

				openIdURLStr = br.readLine();

				System.out.print("Password:");
				br = new BufferedReader(new InputStreamReader(System.in));
				passphrase = br.readLine();
			} catch (IOException e2) {
				fail(" OpenID and password of PCMDI account could not be read.");
			}

			Assert.assertFalse("OpenID of PCMDI account isn't given",
					openIdURLStr == null || openIdURLStr.equals(""));
			Assert.assertFalse("OpenID of PCMDI pass isn't given",
					passphrase == null || passphrase.equals(""));

			pcmdiAuthentication = new PasswordAuthentication(openIdURLStr,
					passphrase.toCharArray());

			// serialize PasswordAuthentication
			ObjectOutputStream out = null;
			try {

				System.out.println(ESGFCredentialsProviderTest.class
						.getResource(".").getPath());

				System.out.println(ESGFCredentialsProviderTest.class
						.getResource("test.xml").getPath());

				URL path = ESGFCredentialsProviderTest.class
						.getResource(PCMDI_PASS_AUTH);

				System.out.println("path: " + path);
				File file = new File(path.toString());
				out = new ObjectOutputStream(new FileOutputStream(file));
				System.out.println("POOOOOOOOOOOOO");
				out.writeObject(pcmdiAuthentication);

			} catch (Exception e) {
				e.printStackTrace();
				fail(" OpenID and password of PCMDI account could not be saved in binary.");
			} finally {
				if (out != null) {
					out.close();
				}
			}

		}

		if (inputDKRZ == null) {
			// asks for DKRZ account
			openIdURLStr = "";
			passphrase = "";

			try {
				System.out.print("DKRZ OpenID URL:");
				BufferedReader br = new BufferedReader(new InputStreamReader(
						System.in));

				openIdURLStr = br.readLine();

				System.out.print("Password:");
				br = new BufferedReader(new InputStreamReader(System.in));
				passphrase = br.readLine();
			} catch (IOException e2) {
				fail(" OpenID and password of DKRZ account could not be read.");
			}

			Assert.assertFalse("OpenID of DKRZ account isn't given",
					openIdURLStr == null || openIdURLStr.equals(""));
			Assert.assertFalse("OpenID of DKRZ pass isn't given",
					passphrase == null || passphrase.equals(""));

			dkrzAuthentication = new PasswordAuthentication(openIdURLStr,
					passphrase.toCharArray());

			// serialize PasswordAuthentication
			ObjectOutputStream out = null;
			try {

				File file = new File(DKRZ_PASS_AUTH);
				out = new ObjectOutputStream(new FileOutputStream(file));
				out.writeObject(dkrzAuthentication);

			} catch (Exception e) {
				fail(" OpenID and password of DKRZ account could not be saved in binary.");
			} finally {
				if (out != null) {
					out.close();
				}
			}
		}
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
	public void getCredentialsWithMyProxyLogon() {
		fail("Not yet implemented");
	}

	@Test
	public void getCredentialsWithMyProxyLogonAndBootstrapTest() {
		fail("Not yet implemented");
	}

	@Test
	public void getCredentialsWithMyProxy206Test() {
		// always with bootstrap
		fail("Not yet implemented");
	}

}
