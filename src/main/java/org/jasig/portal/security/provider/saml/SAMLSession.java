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

import org.apache.http.client.HttpClient;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * This class is used to maintain the state of delegated SAML authentication
 * before, during, and after the authentication.  Please note that some of the
 * methods of this class are package-scoped.  This rather unusual scoping is
 * used to permit access to other classes, most notably {@link SAMLDelegatedAuthenticationService},
 * to methods in this class, but to keep those methods from the public API
 * documentation.
 *  
 * @author Adam Rybicki
 *
 */
public class SAMLSession {
  // The original assertion passed to the portal by the SP
  private String samlAssertion = null;
  
  // HttpClient connection to the WSP.  This is what encapsulates the HTTP session with the WSP
  private HttpClient wspHttpClient = null;
  
  private IdPEPRResolver idpResolver = null;
  
  // Parsed DOM of the SAML assertion
  private Document samlAssertionDom = null;
  
  // SSL Security options for the IdP
  private SSLSecurityWrapper idpSSL = new SSLSecurityImpl();

  /**
   * Public constructor that initializes the SAML session.  This sets up the
   * ThreadSafeConnectionManager because the connection interceptor will be
   * making a secondary connection to authenticate to the IdP while the
   * primary connection is blocked. 
   * 
   * @param samlAssertion SAML assertion that was passed to the portal for authentication
   */
  public SAMLSession(String samlAssertion) {
    // Borrow the SchemeRegistry from DefaultHttpClient and its ConnectionManager
    // There should be a better way of getting a default SchemeRegistry
    DefaultHttpClient client = new DefaultHttpClient ();
    SchemeRegistry registry = client.getConnectionManager().getSchemeRegistry();
    // It seems that empty HttpParams work fine, but as with SchemeRegistry there
    // should be a better way of getting an initialized set.
    HttpParams params = new BasicHttpParams();
    client = new DefaultHttpClient (new ThreadSafeClientConnManager(params, registry), params); 
    client.addRequestInterceptor(new HttpRequestPreprocessor());
    client.addResponseInterceptor(new HttpRequestPostprocessor(this));
    setHttpClient(client);
    this.samlAssertion = samlAssertion;
  }

  /**
   * Returns the same String representation of SAML assertion that was passed
   * to the constructor.
   * 
   * @return the SAML assertion
   */
  public String getSamlAssertion() {
    return samlAssertion;
  }

  /**
   * Returns the DOM representation of the SAML assertion.  Assertions are
   * usually digitally signed, so it is important to keep them unchanged.
   * @return the samlAssertionDom
   */
  public Document getSamlAssertionDom() {
    return samlAssertionDom;
  }

  /**
   * This method is intentionally package-scoped to maintain access to other
   * classed from this package, but to keep it from the public API documentation.
   */
  void setSamlAssertionDom(Document samlAssertionDom) {
    this.samlAssertionDom = samlAssertionDom;
  }

  /**
   * Returns the Apache Commons HTTP Client that is set up with an authenticated
   * session to the WSP.  Since the session management of the WSP is
   * WSP-specific, there is no way to guarantee that this HttpClient
   * will continue the session set up by the authentication process, but
   * because Apache Commons HTTP Client works much like a browser, it should
   * continue sending cookies that were established during authentication.
   * Shibboleth SP was specifically tested, and its session works as expected.
   * It is probably important to use the same scheme, host, and base context
   * as those used in the initial {@link Resource} passed during authentication.
   *  
   * @return wspHttpClient instance of Apache Commons HTTP Client {@link org.apache.http.client.HttpClient} class
   */
  public HttpClient getHttpClient() {
    return wspHttpClient;
  }

  /**
   * @param wspHttpClient the wspHttpClient to set
   */
  protected void setHttpClient(HttpClient wspHttpClient) {
    this.wspHttpClient = wspHttpClient;
  }

  /**
   * @return the idpResolver
   * @see setIdPResolver
   */
  public IdPEPRResolver getIdpResolver() {
    return idpResolver;
  }

  /**
   * Provide an implementation of the IdPEPRResolver interface to resolve the
   * IdP endpoint to which the delegated SAML authentication requests must be
   * presented.  The default implementation, {@link AssertionIdPResolver}
   * resolved the endpoint from SAML assertion.  Shibboleth IdP provides an
   * endpoint reference in the assertion.
   * 
   * @param idpResolver the implementation of the {@link IdPEPRResolver} interface
   */
  public void setIdpResolver(IdPEPRResolver idpResolver) {
    this.idpResolver = idpResolver;
  }

  /**
   * This method is used to specify the private key and certificate to use
   * to identify the client to the IdP.  The TLS layer will present the certificate
   * to the IdP.  Because, as far as the IdP is concerned, the portal and its SP
   * are one and the same, the parameters to this method will be the PEM-encoded
   * private key and certificate files that the SP uses.
   * 
   * @param pkFile file name of the PEM-encoded private key
   * @param certFile file name of the PEM-encoded certificate
   */
  public void setIdPClientPrivateKeyAndCert (String pkFile, String certFile) {
    this.idpSSL.setSSLClientPrivateKeyAndCert(pkFile, certFile);
  }
  
  /**
   * This method provides an alternative method of providing client TLS certificate
   * to send to the IdP to identify the client.
   * 
   * @param ks file name of Java KeyStore containing the certificate and private
   *           key to present to the IdP 
   * @param pass KeyStore password (must not be null)
   * @see #setIdPClientPrivateKeyAndCert()
   */
  public void setIdPClientKeystore (String ks, String pass) {
    this.idpSSL.setSSLClientKeystore(ks, pass);
  }
  
  /**
   * This method allows to specify a Java TrustStore of server X.509 certificates
   * to trust.  These may be either signing Certificate Authority (CA) certificates
   * of self-signed certificates for IdPs to trust.  Java normally trusts all
   * servers that present valid certificates signed by a recognized CA.  This method
   * allows to securely communicate with institution-specific IdP.
   * 
   * @param ks file name of a Java KeyStore
   * @param pass password to access the KeyStore
   */
  public void setIdPClientTrustStore (String ks, String pass) {
    this.idpSSL.setSSLTrustStore(ks, pass);
  }

  /**
   * This method allows to specify the public key(s) to verify and trust when
   * communicating with the IdP.  Shibboleth SP can provide the public key(s)
   * of the IdP to trust.  When the caller specifies the public key(s) to trust,
   * the connection to the IdP will not proceed if the IdP does not present
   * a matching public key.
   * 
   * @param publicKeys Base64-encoded public key(s) to verify before allowing
   *                   a connection to the IdP to proceed.
   */
  public void setIdPServerPublicKeys (String publicKeys) {
    this.idpSSL.setSSLServerPublicKeys(publicKeys);
  }

  /**
   * Returns an instance of {@link org.apache.http.conn.ssl.SSLSocketFactory}
   * suitable for use with the Apache Commons HTTP Client.  This socket factory
   * is set up with the previously set keys and/or certificates for communicating
   * with the IdP.
   * 
   * @return SSLSocketFactory suitable for use with the Apache Commons HTTP Client
   */
  public SSLSocketFactory getIdPSocketFactory () {
    return this.idpSSL.getSSLSocketFactory();
  }
  
}
