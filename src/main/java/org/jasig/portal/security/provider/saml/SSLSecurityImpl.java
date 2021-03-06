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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.UUID;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.http.conn.ssl.SSLSocketFactory;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.x509.X509Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class wraps some SSL options for enforcing security then communicating
 * with a SAML IdP or a SAML-protected Web Service Provider.
 * 
 * @author Adam Rybicki
 */
public class SSLSecurityImpl implements SSLSecurityWrapper {
  protected final Logger logger = LoggerFactory.getLogger(this.getClass());
  
  private KeyStore keyStore = null;
  private String keyStorePass = null;
  private KeyStore trustStore = null;
  private String publicKeys;
  
  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  /* (non-Javadoc)
   * @see edu.uchicago.portal.portlets.samltest.domain.SSLSecurityWrapper#getSSLSocketFactory()
   */
    public SSLSocketFactory getSSLSocketFactory() {
        try {
            //Implementation taken from SSLSocketFactory constructor with added support for a trust-all
            //trust store if no trustStore is explicitly configured and public keys are available
            KeyManager[] keymanagers = null;
            if (keyStore != null) {
                keymanagers = createKeyManagers(keyStore, keyStorePass);
            }
            TrustManager[] trustmanagers = null;
            if (trustStore != null) {
                trustmanagers = createTrustManagers(trustStore);
            }
            else if (publicKeys != null) {
                trustmanagers = new TrustManager[] { TrustAllX509TrustManager.INSTANCE };
            }

            final SSLContext sslcontext = SSLContext.getInstance(SSLSocketFactory.TLS);
            sslcontext.init(keymanagers, trustmanagers, null);

            if (publicKeys != null) {
                return new PublicKeyVerifyingSSLSocketFactory(sslcontext, publicKeys);
            }

            return new SSLSocketFactory(sslcontext);
        }
        catch (Exception ex) {
            throw new DelegatedAuthenticationRuntimeException("Error dealing with SSL.  See stack trace for details.", ex);
        }
    }

  private static KeyManager[] createKeyManagers(final KeyStore keystore, final String password)
      throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
      if (keystore == null) {
          throw new IllegalArgumentException("Keystore may not be null");
      }
      KeyManagerFactory kmfactory = KeyManagerFactory.getInstance(
          KeyManagerFactory.getDefaultAlgorithm());
      kmfactory.init(keystore, password != null ? password.toCharArray(): null);
      return kmfactory.getKeyManagers(); 
  }

  private static TrustManager[] createTrustManagers(final KeyStore keystore)
      throws KeyStoreException, NoSuchAlgorithmException { 
      if (keystore == null) {
          throw new IllegalArgumentException("Keystore may not be null");
      }
      TrustManagerFactory tmfactory = TrustManagerFactory.getInstance(
          TrustManagerFactory.getDefaultAlgorithm());
      tmfactory.init(keystore);
      return tmfactory.getTrustManagers();
  }

  /* (non-Javadoc)
   */
  private void setSSLClientCredentials(PrivateKey pk, Certificate cert) throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException {
    this.logger.info("Private key: [{}].", pk.toString());
    this.logger.info("Certificate: [{}].", cert.toString());
    KeyStore ks = KeyStore.getInstance("JKS", "SUN");
    ks.load(null, null);
    Certificate[] certificates = new Certificate[1];
    certificates[0] = cert;
    String keystorePass = UUID.randomUUID().toString();
    ks.setKeyEntry("sp", pk, keystorePass.toCharArray(), certificates);
    this.keyStore = ks;
    this.keyStorePass = keystorePass;
  }

  /* (non-Javadoc)
   */
  public void setSSLClientKeystore(String ksFile, String pass) {
    try {
      KeyStore ks = loadKeyStoreFromFile(ksFile, pass);
      this.keyStore = ks;
      this.keyStorePass = pass;
    }
    catch (Exception ex) {
      throw new DelegatedAuthenticationRuntimeException("Error dealing with SSL.  See stack trace for details.", ex);
    }
  }

  /*
   * Utility method to load a KeyStore fom  file
   */
  private KeyStore loadKeyStoreFromFile(String ksFile, String pass) throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException {
    FileInputStream fis = new FileInputStream(ksFile);
    try {
        KeyStore ks = KeyStore.getInstance("JKS", "SUN");
        ks.load(fis, pass.toCharArray());
        return ks;
    }
    finally {
        fis.close();
    }
  }

  /* (non-Javadoc)
   */
  public void setSSLTrustStore(String ksFile, String pass) {
    try {
      KeyStore ks = loadKeyStoreFromFile(ksFile, pass);
      this.trustStore = ks;
    }
    catch (Exception ex) {
      throw new DelegatedAuthenticationRuntimeException("Error dealing with SSL.  See stack trace for details.", ex);
    }
  }

  /* (non-Javadoc)
   */
  public void setSSLClientPrivateKeyAndCert(String pkFile, String certFile) {
    PrivateKey key;
    try {
      key = SecurityHelper.decodePrivateKey(new File(pkFile), null);
      Collection<X509Certificate> certs = X509Util.decodeCertificate(new File(certFile));
      X509Certificate cert = certs.iterator().next();
      setSSLClientCredentials(key, cert);
    }
    catch (Exception ex) {
      throw new DelegatedAuthenticationRuntimeException("Error dealing with SSL.  See stack trace for details.", ex);
    }
  }

  public void setSSLServerPublicKeys(String encodedKeys) {
    this.publicKeys = encodedKeys;
  }


}
