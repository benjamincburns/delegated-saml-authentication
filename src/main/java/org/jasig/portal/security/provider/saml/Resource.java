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

import java.net.MalformedURLException;
import java.net.URL;

import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.ssl.SSLSocketFactory;


/**
 * A class that "wraps" a simple resource that is retrieved from a Web Service
 * Provider (WSP) as a String.  The resource is represented by a URL.
 * @author Adam Rybicki
 */
public class Resource {
  private String resourceUrl = "";
  private String resource = "";

  // SSL Security options for the WSP
  private SSLSecurityWrapper wspSSL = new SSLSecurityImpl();
  
  /**
   * Get the resource as it was retrieved from the WSP.
   * @return the resource represented as a String
   */
  public String getResource() {
    return resource;
  }

  /**
   * Set the resource as it was retrieved from the WSP.
   * @param resource the resource to set
   */
  public void setResource(String resource) {
    this.resource = resource;
  }

  /**
   * Get the URL of the resource.
   * @return the resourceUrl
   */
  public String getResourceUrl() {
    return resourceUrl;
  }

  /**
   * Get the URL of the resource.
   * @param resourceUrl the resourceUrl to set
   */
  public void setResourceUrl(String resourceUrl) {
    this.resourceUrl = resourceUrl;
  }

  /**
   * This method is used to specify the private key and certificate to use
   * to identify the client to the WSP.  The TLS layer will present the certificate
   * to the WSP.
   * 
   * @param pkFile file name of the PEM-encoded private key
   * @param certFile file name of the PEM-encoded certificate
   */
  
  public void setWSPClientPrivateKeyAndCert (String pkFile, String certFile) {
    this.wspSSL.setSSLClientPrivateKeyAndCert(pkFile, certFile);
  }
  
  /**
   * This method provides an alternative method of providing client TLS certificate
   * to send to the WSP to identify the client.
   * 
   * @param ks file name of Java KeyStore containing the certificate and private
   *           key to present to the WSP 
   * @param pass KeyStore password (must not be null)
   * @see #setWSPClientPrivateKeyAndCert()
   */
  public void setWSPClientKeystore (String ks, String pass) {
    this.wspSSL.setSSLClientKeystore(ks, pass);
  }
  
  /**
   * This method allows to specify a Java TrustStore of server X.509 certificates
   * to trust.  These may be either signing Certificate Authority (CA) certificates
   * of self-signed certificates for WSPs to trust.  Java normally trusts all
   * servers that present valid certificates signed by a recognized CA.  This method
   * allows to securely communicate with institution-specific WSP.
   * 
   * @param ks file name of a Java KeyStore
   * @param pass password to access the KeyStore
   */
  public void setWSPClientTrustStore (String ks, String pass) {
    this.wspSSL.setSSLTrustStore(ks, pass);
  }

  /**
   * Returns an instance of {@link org.apache.http.conn.ssl.SSLSocketFactory}
   * suitable for use with the Apache Commons HTTP Client.  This socket factory
   * is set up with the previously set keys and/or certificates for communicating
   * with the WSP.
   * 
   * @return SSLSocketFactory suitable for use with the Apache Commons HTTP Client
   */
  public SSLSocketFactory getWSPSocketFactory () {
    return this.wspSSL.getSSLSocketFactory();
  }

  /**
   * Sets up the SSL parameters of a connection to the WSP, including the
   * client certificate and server certificate trust.  The program that set up
   * the SAMLSession object is responsible for providing these optional SSL
   * parameters.
   *  
   * @param samlSession SAMLSession that already must contain a valid HttpClient for the WSP
   * @param resource Resource wrapper class that contains a resource URL
   * @throws MalformedURLException 
   */
  public void setupWSPClientConnection(SAMLSession samlSession) throws MalformedURLException {
    URL url = new URL(resourceUrl);
    String protocol = url.getProtocol();
    int port = url.getPort();
    
    // Unless we are using SSL/TLS, there is no need to do the socket factory
    
    if (protocol.equalsIgnoreCase("https")) {
      SSLSocketFactory socketFactory = getWSPSocketFactory();
      
      if (port == -1)
        port = 443;

      Scheme sch = new Scheme(protocol, socketFactory, port);
      samlSession.getHttpClient().getConnectionManager().getSchemeRegistry().unregister(protocol);
      samlSession.getHttpClient().getConnectionManager().getSchemeRegistry().register(sch);
    }
  }

}
