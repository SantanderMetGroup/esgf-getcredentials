package es.unican.meteo.esgf.myproxyclient;

import java.io.IOException;
import java.security.GeneralSecurityException;

import es.unican.meteo.esgf.common.ESGFCredentials;

public interface MyProxyProvider {
	/**
	 * Get {@link ESGFCredentials} from ESGF.
	 * 
	 * @param bootstrap
	 *            true to bootstrapping certificates and false otherwise
	 * @param myProxyParams
	 *            parameters to configure MyProxy for retrieving credentials
	 *            from a MyProxy server
	 * @param caDirectory
	 *            directory of trust roots certs
	 * @return
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	public ESGFCredentials getESGFCredentials(boolean bootstrap,
			MyProxyParameters myProxyParams, String caDirectory)
			throws IOException, GeneralSecurityException;
}
