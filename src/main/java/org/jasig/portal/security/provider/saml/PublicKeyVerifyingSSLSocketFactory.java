package org.jasig.portal.security.provider.saml;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.params.HttpParams;
import org.opensaml.xml.security.SecurityHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class extends the Apache Commons HTTP Client SSLSocketFactory to support
 * the verification of the server's public key against supplied public key.  If
 * an attempt is made to connec to to a server that does not present a matching
 * public key, the connection will be terminated.
 *  

 * @author Adam Rybicki
 */
public class PublicKeyVerifyingSSLSocketFactory extends SSLSocketFactory {
  
  Logger log = LoggerFactory.getLogger(SSLSocketFactory.class);
  private PublicKey publicKey = null;

  /**
   * @see org.apache.http.conn.ssl.SSLSocketFactory#SSLSocketFactory(KeyStore)
   */
  public PublicKeyVerifyingSSLSocketFactory(KeyStore ks) throws KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
    super(ks);
  }

  /**
   * @see org.apache.http.conn.ssl.SSLSocketFactory#SSLSocketFactory(KeyStore, String)
   */
  public PublicKeyVerifyingSSLSocketFactory(KeyStore keyStore, String keyStorePass) throws KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
    super(keyStore, keyStorePass);
  }

  /**
   * @see org.apache.http.conn.ssl.SSLSocketFactory#SSLSocketFactory(KeyStore, String, KeyStore)
   */
  public PublicKeyVerifyingSSLSocketFactory(KeyStore keyStore, String keyStorePass, KeyStore trustStore) throws KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
    super(keyStore, keyStorePass, trustStore);
  }

  /**
   * Set the Base64-encoded public key(s) to validate.  This method decodes the
   * passed public key and keeps it for verification at the time a connection is attempted.
   * 
   * @param encodedPublicKeys Base64-encoded public key(s)
   * @throws KeyException
   */
  public void setEncodedPublicKeys(String encodedPublicKeys) throws KeyException {
    // Need to Base64-decode the bytes first
    byte[] decodedBytes = Base64.decodeBase64(encodedPublicKeys.getBytes());
    publicKey = SecurityHelper.decodePublicKey(decodedBytes, null);
  }

  
  /**
   * This method makes a connection to the server by utilizing the base class
   * method, but it adds a validation of the server's public key if one was
   * supplied previously.
   * 
   * @see org.apache.http.conn.ssl.SSLSocketFactory#connectSocket(java.net.Socket, java.lang.String, int, java.net.InetAddress, int, org.apache.http.params.HttpParams)
   */
  @Override
  public Socket connectSocket(final Socket sock,final String host,final int port,final InetAddress localAddress,int localPort,final HttpParams params) throws IOException {
    SSLSocket newSocket = (SSLSocket) super.connectSocket(sock, host, port, localAddress, localPort, params);
    
    if (publicKey != null) {
      SSLSession session = newSocket.getSession();
      Certificate[] certs = session.getPeerCertificates();
      boolean matchFound = false;
      
      for (int i = 0;i < certs.length;i++) {
        X509Certificate x509 = (X509Certificate) certs[i];
        PublicKey certKey = x509.getPublicKey();
        
        if (certKey.equals(publicKey)) {
          matchFound = true;
          break;
        }
      }
      if (!matchFound) {
        newSocket.close();
        throw new IOException ("Unable to verify the server's public key");
      }
    }
    return newSocket;
  }
}
