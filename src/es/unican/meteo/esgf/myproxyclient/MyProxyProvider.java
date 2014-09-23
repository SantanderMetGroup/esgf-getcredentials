package es.unican.meteo.esgf.myproxyclient;

import java.io.IOException;
import java.security.GeneralSecurityException;

import es.unican.meteo.esgf.common.ESGFCredentials;

public interface MyProxyProvider {
	public ESGFCredentials getESGFCredentials(MyProxyParameters myProxyParams,
			String caDirectory) throws IOException, GeneralSecurityException;
}
