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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.xml.XMLConstants;
import javax.xml.namespace.NamespaceContext;

/**
 * This class is needed for resolving the XML namespace prefixes used during
 * delegated SAML authentication
 *  
 * @author Adam Rybicki
 */
public class SAMLNamespaceContext implements NamespaceContext {
  private static final String[] prefixes = {
    "saml2",
    "ds",
    "S",
    "soap",
    "env",
    "paos",
    "ecp",
    "samlp",
    "wsa",
    "sbf",
    "sb",
    "disco",
  };

  private static final String[] uris = {
    "urn:oasis:names:tc:SAML:2.0:assertion",
    "http://www.w3.org/2000/09/xmldsig#",
    "http://schemas.xmlsoap.org/soap/envelope/",
    "http://schemas.xmlsoap.org/soap/envelope/",
    "http://www.w3.org/2003/05/soap-envelope",
    "urn:liberty:paos:2003-08",
    "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp",
    "urn:oasis:names:tc:SAML:2.0:protocol",
    "http://www.w3.org/2005/08/addressing",
    "urn:liberty:sb",
    "urn:liberty:sb:2006-08",
    "urn:liberty:disco:2006-08",
  };
  
  private List<String> prefixList = new ArrayList<String>();
  private Map<String,String> prefixToURI = new HashMap<String,String>();
  private Map<String,String> uriToPrefix = new HashMap<String,String>();
  
  public SAMLNamespaceContext() {
    for(int i = 0;i < prefixes.length;i++) {
      prefixList.add(prefixes[i]);
      prefixToURI.put(prefixes[i], uris[i]);
      uriToPrefix.put(uris[i], prefixes[i]);
    }
  }

  /* (non-Javadoc)
   * @see javax.xml.namespace.NamespaceContext#getNamespaceURI(java.lang.String)
   */
  @Override
  public String getNamespaceURI(String prefix) {
    String uri = prefixToURI.get(prefix);
    
    if (uri != null)
      return uri;
    else
      return XMLConstants.NULL_NS_URI;
  }

  /* (non-Javadoc)
   * @see javax.xml.namespace.NamespaceContext#getPrefix(java.lang.String)
   */
  @Override
  public String getPrefix(String uri) {
    return uriToPrefix.get(uri);
  }

  /* (non-Javadoc)
   * @see javax.xml.namespace.NamespaceContext#getPrefixes(java.lang.String)
   */
  @SuppressWarnings("unchecked")
  @Override
  public Iterator getPrefixes(String arg0) {
    return prefixList.iterator();
  }

}
