package es.unican.meteo.esgf.myproxyclient;


/**
 * Parameters to configure MyProxy for retrieving credentials from a MyProxy
 * server.
 * 
 * @author Karem Terry
 *
 */
public class MyProxyParameters {

	private String userName;
	private String password;
	private String host;
	private int port;
	private int lifetime;
	private boolean requestTrustRoots;

	/**
	 * Constructor
	 * 
	 * @param userName
	 * @param password
	 * @param host
	 * @param port
	 * @param lifetime
	 * @param requestTrustRoots
	 */
	public MyProxyParameters(String userName, String password, String host,
			int port, int lifetime, boolean requestTrustRoots) {
		super();
		this.userName = userName;
		this.password = password;
		this.host = host;
		this.port = port;
		this.lifetime = lifetime;
		this.requestTrustRoots = requestTrustRoots;
	}

	/**
	 * Gets the MyProxy username.
	 * 
	 * @return the MyProxy userName
	 */
	public String getUserName() {
		return userName;
	}

	/**
	 * Gets the MyProxy password.
	 * 
	 * @return the MyProxy password
	 */
	public String getPassword() {
		return password;
	}

	/**
	 * Gets the hostname of the MyProxy server.
	 * 
	 * @return MyProxy server hostname
	 */
	public String getHost() {
		return host;
	}

	/**
	 * Gets the port of the MyProxy server.
	 * 
	 * @return MyProxy server port
	 */
	public int getPort() {
		return port;
	}

	/**
	 * Gets the requested credential lifetime.
	 * 
	 * @return Credential lifetime
	 */
	public int getLifetime() {
		return lifetime;
	}

	/**
	 * Gets whether to request trust roots (CA certificates, CRLs, signing
	 * policy files) from the MyProxy server
	 * 
	 * @return the If true, request trust roots. If false, don't request trust
	 *         roots.
	 */
	public boolean isRequestTrustRoots() {
		return requestTrustRoots;
	}

	/**
	 * Sets the MyProxy username.
	 * 
	 * @param userName
	 *            the userName to set
	 */
	public void setUserName(String userName) {
		this.userName = userName;
	}

	/**
	 * Sets the MyProxy password.
	 * 
	 * @param password
	 *            the password to set
	 */
	public void setPassword(String password) {
		this.password = password;
	}

	/**
	 * Sets the hostname of the MyProxy server. Defaults to localhost.
	 * 
	 * @param host
	 *            MyProxy server hostname
	 */
	public void setHost(String host) {
		this.host = host;
	}

	/**
	 * Sets the port of the MyProxy server.
	 * 
	 * @param MyProxy
	 *            server port
	 */
	public void setPort(int port) {
		this.port = port;
	}

	/**
	 * Sets the requested credential lifetime.
	 * 
	 * @param lifetime
	 *            Credential lifetime
	 */
	public void setLifetime(int lifetime) {
		this.lifetime = lifetime;
	}

	/**
	 * Sets whether to request trust roots (CA certificates, CRLs, signing
	 * policy files) from the MyProxy server.
	 * 
	 * @param requestTrustRoots
	 *            If true, request trust roots. If false, don't request trust
	 *            roots.
	 */
	public void setRequestTrustRoots(boolean requestTrustRoots) {
		this.requestTrustRoots = requestTrustRoots;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "MyProxyParameters [userName=" + userName + ", password="
				+ password + ", host=" + host + ", port=" + port
				+ ", lifetime=" + lifetime + ", requestTrustRoots="
				+ requestTrustRoots + "]";
	}

}
