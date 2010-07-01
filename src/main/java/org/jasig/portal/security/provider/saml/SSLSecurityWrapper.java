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

import org.apache.http.conn.ssl.SSLSocketFactory;

/**
 * This interface defines the methods needed to contain SSL security options
 * like private key, client certificate, etc.  In context of this project
 * different security options may be needed for either the IdP or the WSP.
 *
 * @author arybicki
 */
public interface SSLSecurityWrapper {
  
  /**
   * Set the credentials for client TSL certificate authentication.
   * These files should be in PEM-encoded format.
   * 
   * @param pkFile - name of the file containing the private key
   * @param certFile - name of the file containing the certificate
   */
  public void setSSLClientPrivateKeyAndCert (String pkFile, String certFile);
  
  /**
   * Set the credentials for client TSL certificate authentication
   * 
   * @param ks File name of a Java KeyStore containing the private key and certificate
   * @param pass Password for the Java KeyStore
   */
  public void setSSLClientKeystore (String ks, String pass);
  
  /**
   * Set the KeyStore of server certificates to trust.  This overrides the
   * default Java behavior, which is to trust all servers that present valid
   * certificates signed by a trusted Certificte Authorities (CA).  The KeyStore
   * set here may contain servers' self-signed certificates or certificates
   * of local CA(s).
   * 
   * @param ks Java KeyStore containing certificates to trust
   * @param pass Password of the KeyStore
   */
  public void setSSLTrustStore (String ks, String pass);
  
  /**
   * Set the public keys of server to trust.  This overrides the
   * default Java behavior, which is to trust all servers that present valid
   * certificates signed by a trusted Certificte Authorities (CA).  After this
   * method is called, only servers that present X.509 certificates containing
   * a matching public key will be trusted.
   * 
   * @param encodedKeys Base64-encoded public key(s)
   */
  public void setSSLServerPublicKeys (String encodedKeys);
  
  /**
   * Get an instance of SSL socket factory based on the supplied credentials.
   * Used to enforce the client certificate and server trust options set.
   * 
   * @return A SSLSocketFactory suitable for use with Apache Commons HTTP Client
   */
  public SSLSocketFactory getSSLSocketFactory();

}
