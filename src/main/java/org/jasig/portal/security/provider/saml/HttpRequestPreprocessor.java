package org.jasig.portal.security.provider.saml;

import java.io.IOException;

import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.protocol.HttpContext;

/**
 * This class is used to set the PAOS headers on every request made to a WSP.
 * 
 * @author Adam Rybicki
 */
public final class HttpRequestPreprocessor implements HttpRequestInterceptor {

  /* (non-Javadoc)
   * @see org.apache.http.HttpRequestInterceptor#process(org.apache.http.HttpRequest, org.apache.http.protocol.HttpContext)
   */
  @Override
  public void process(final HttpRequest req, final HttpContext ctx) throws HttpException, IOException {
    req.addHeader("Accept", SAMLConstants.HTTP_HEADER_PAOS_CONTENT_TYPE);
    req.addHeader("PAOS", SAMLConstants.HTTP_HEADER_PAOS);
  }

}
