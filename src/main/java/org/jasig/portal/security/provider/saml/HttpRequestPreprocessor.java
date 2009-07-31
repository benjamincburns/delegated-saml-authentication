/**
 * Copyright 2009 University of Chicago
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
