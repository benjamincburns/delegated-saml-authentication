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

import org.w3c.dom.Document;
import org.w3c.dom.Element;


/**
 * A class that "wraps" a simple resource that is retrieved from a Web Service
 * Provider (WSP) as a String.  The resource is represented by a URL.
 * @author Adam Rybicki
 */
public class DelegatedSAMLAuthenticationState {

  // The IdP
  private String idp = null;
  
  // The IdP endpoint, or URL, where the ECP will request a delegated authentication assertion
  private String idpEndpoint = null;
  
  // SOAP request from the WSP
  private byte[] soapRequest = null;
  
  // DOM of the SOAP request to manipulate
  private Document soapRequestDom = null;
  
  // URL where to send the SOAP response, or AuthnRequest response
  private String responseConsumerURL = null;
  
  // PAOS MessageID
  private String paosMessageID = null;
  
  // RelayState element to use for passing the SOAP Response, or AuthnRequest
  // response, back to the WSP
  private Element relayStateElement = null;
  
  // The modified SOAP Request for sending to the IdP
  private String modifiedSOAPRequest = null; 
  
  // SOAP response from the IdP
  private String soapResponse = null;
  
  // Modified SOAP response for sending back to the SP
  private String modifiedSOAPResponse = null;
  
  /**
   * Return the IdP entityID.  This is not the IdP endpoint, or a URL.
   * @return the idp
   * @see getIdPEndpoint
   */
  public String getIdp() {
    return idp;
  }

  /**
   * Set the IdP entityID.
   * @param idp the idp to set
   * @see setIdPEndpoint
   */
  public void setIdp(String idp) {
    this.idp = idp;
  }

  /**
   * Obtains the resolved IdP endpoint to which the library presents delegated
   * SAML authentication request.
   * 
   * @return the idpEndpoint
   */
  public String getIdpEndpoint() {
    return idpEndpoint;
  }

  /**
   * Used by the implementation of the {@link IdPEPRResolver} to set the resolved
   * IdP endpoint where the delegated SAML authentication request will be delivered.
   * 
   * @param idpEndpoint the idpEndpoint to set
   */
  public void setIdpEndpoint(String idpEndpoint) {
    this.idpEndpoint = idpEndpoint;
  }

  /**
   * This method is intentionally package-scoped to maintain access to other
   * classed from this package, but to keep it from the public API documentation.
   */
  byte[] getSoapRequest() {
    return soapRequest;
  }

  /**
   * This method is intentionally package-scoped to maintain access to other
   * classed from this package, but to keep it from the public API documentation.
   */
  void setSoapRequest(byte[] soapRequest) {
    this.soapRequest = soapRequest;
  }

  /**
   * This method is intentionally package-scoped to maintain access to other
   * classed from this package, but to keep it from the public API documentation.
   */
  Document getSoapRequestDom() {
    return soapRequestDom;
  }

  /**
   * This method is intentionally package-scoped to maintain access to other
   * classed from this package, but to keep it from the public API documentation.
   */
  void setSoapRequestDom(Document soapRequestDom) {
    this.soapRequestDom = soapRequestDom;
  }

  /**
   * This method is intentionally package-scoped to maintain access to other
   * classed from this package, but to keep it from the public API documentation.
   */
  String getResponseConsumerURL() {
    return responseConsumerURL;
  }

  /**
   * This method is intentionally package-scoped to maintain access to other
   * classed from this package, but to keep it from the public API documentation.
   */
  void setResponseConsumerURL(String responseConsumerURL) {
    this.responseConsumerURL = responseConsumerURL;
  }

  /**
   * This method is intentionally package-scoped to maintain access to other
   * classed from this package, but to keep it from the public API documentation.
   */
  String getPaosMessageID() {
    return paosMessageID;
  }

  /**
   * This method is intentionally package-scoped to maintain access to other
   * classed from this package, but to keep it from the public API documentation.
   */
  void setPaosMessageID(String paosMessageID) {
    this.paosMessageID = paosMessageID;
  }

  /**
   * This method is intentionally package-scoped to maintain access to other
   * classed from this package, but to keep it from the public API documentation.
   */
  Element getRelayStateElement() {
    return relayStateElement;
  }

  /**
   * This method is intentionally package-scoped to maintain access to other
   * classed from this package, but to keep it from the public API documentation.
   */
  void setRelayStateElement(Element relayStateElement) {
    this.relayStateElement = relayStateElement;
  }

  /**
   * This method is intentionally package-scoped to maintain access to other
   * classed from this package, but to keep it from the public API documentation.
   */
  String getModifiedSOAPRequest() {
    return modifiedSOAPRequest;
  }

  /**
   * This method is intentionally package-scoped to maintain access to other
   * classed from this package, but to keep it from the public API documentation.
   */
  void setModifiedSOAPRequest(String modifiedSOAPRequest) {
    this.modifiedSOAPRequest = modifiedSOAPRequest;
  }

  /**
   * This method is intentionally package-scoped to maintain access to other
   * classed from this package, but to keep it from the public API documentation.
   */
  String getSoapResponse() {
    return soapResponse;
  }

  /**
   * This method is intentionally package-scoped to maintain access to other
   * classed from this package, but to keep it from the public API documentation.
   */
  void setSoapResponse(String soapResponse) {
    this.soapResponse = soapResponse;
  }

  /**
   * This method is intentionally package-scoped to maintain access to other
   * classed from this package, but to keep it from the public API documentation.
   */
  String getModifiedSOAPResponse() {
    return modifiedSOAPResponse;
  }

  /**
   * This method is intentionally package-scoped to maintain access to other
   * classed from this package, but to keep it from the public API documentation.
   */
  void setModifiedSOAPResponse(String modifiedSOAPResponse) {
    this.modifiedSOAPResponse = modifiedSOAPResponse;
  }

}
