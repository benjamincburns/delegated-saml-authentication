/**
 * Licensed to Jasig under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Jasig licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a
 * copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.jasig.portal.security.provider.saml;

import org.apache.http.*;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;

import java.io.IOException;

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
  public void process(HttpResponse res, HttpContext ctx) throws HttpException, IOException {
    Header actionHeader = res.getFirstHeader("SoapAction");

      if (actionHeader != null &&
              actionHeader.getValue().equalsIgnoreCase("http://www.oasis-open.org/committees/security")) {
          HttpEntity entity = res.getEntity();
          HttpResponse authnResponse = samlService.authenticate(samlSession, EntityUtils.toByteArray(entity));
        
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
          for (Header header : headers) {
              res.removeHeader(header);
          }
          // Replace with the new headers
          headers = authnResponse.getAllHeaders();
          for (Header header : headers) {
              res.addHeader(header);
          }

          res.setEntity(authnResponse.getEntity());
          res.setStatusLine(authnResponse.getStatusLine());
          res.setLocale(authnResponse.getLocale());
      }

  }
}
