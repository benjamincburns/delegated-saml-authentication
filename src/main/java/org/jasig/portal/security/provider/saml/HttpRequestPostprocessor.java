package org.jasig.portal.security.provider.saml;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpException;
import org.apache.http.HttpResponse;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.HttpStatus;
import org.apache.http.ProtocolVersion;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicStatusLine;
import org.apache.http.protocol.HttpContext;

/**
 * This class intercepts the HTTP responses and looks for the WSP
 * authentication requests.  These are recognized by the Content-Type matching
 * the PAOS content type.  WSP sending this content type can only mean one thing:
 * authentication is required and the payload contains a SOAP authentication
 * request to the IdP.
 * 
 * @author Adam Rybicki
 */
public final class HttpRequestPostprocessor implements HttpResponseInterceptor {
  private SAMLSession samlSession;
  private static SAMLDelegatedAuthenticationService samlService = new SAMLDelegatedAuthenticationService();
  
  public HttpRequestPostprocessor(SAMLSession samlSession) {
    this.samlSession = samlSession;
  }

  /**
   * This method triggers delegated SAML authentication when it is requested
   * by the WSP.  After a successful authentication, this method attempts
   * to redirect the request to the location identified by the WSP at the end
   * of the delegated SAML authentication.  To do that, this method changes the
   * HTTP status to a 302 and sets the Location header accordingly.
   * 
   * @see org.apache.http.HttpResponseInterceptor#process(org.apache.http.HttpResponse, org.apache.http.protocol.HttpContext)
   */
  @Override
  public void process(HttpResponse res, HttpContext ctx) throws HttpException, IOException {
    Header contentTypes[] = res.getHeaders("Content-Type");
    
    for (Header contentType : contentTypes) {
      if (contentType.getValue().equals(SAMLConstants.HTTP_HEADER_PAOS_CONTENT_TYPE)) {
        HttpEntity entity = res.getEntity();
        // This cast from long to int should be safe, as the SOAP AuthnRequest
        // should not be larger than 2GB
        int contentLength = (int)entity.getContentLength();
        ByteArrayOutputStream os = new ByteArrayOutputStream(contentLength);
        entity.writeTo(os);
        os.close();
        byte[] paosBytes = os.toByteArray();
        HttpResponse authnResponse = samlService.authenticate(samlSession, paosBytes);
        
        /*
         * The following logic may require enhancing in the future.  It attempts to copy the result
         * of the delegated SAML authentication to the original HttpResponse, which triggered
         * the authentication.  This will most often result in a redirection to the originally
         * requested resource.  However, the WSP may be replaying the HTTP POST form data,
         * which may not result in redirection.
         * 
         * Basically, we need to make the original request return what the successful authentication
         * result returned.
         */
        // Remove original headers
        Header[] headers = res.getAllHeaders();
        for (Header header : headers)
          res.removeHeader(header);
        // Replace with the new headers
        headers = authnResponse.getAllHeaders();
        for (Header header : headers)
          res.addHeader(header);
        
        res.setEntity(authnResponse.getEntity());
        res.setStatusLine(authnResponse.getStatusLine());
        res.setLocale(authnResponse.getLocale());
        break;
      }
    }
    
  }
}
