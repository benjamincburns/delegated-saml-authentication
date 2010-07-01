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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import java.util.UUID;

import javax.xml.soap.MessageFactory;
import javax.xml.soap.Name;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPConstants;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFault;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.HttpVersion;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.params.HttpClientParams;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;
import org.apache.http.params.HttpProtocolParams;
import org.apache.http.protocol.HTTP;
import org.apache.xerces.parsers.DOMParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.DOMConfiguration;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXNotRecognizedException;
import org.xml.sax.SAXNotSupportedException;

/**
 * <p>This class implements the delegated SAML authentication protocol.  Delegated
 * SAML authentication is most useful for portals, which often act as proxies
 * on behalf of the logged on users.  The portal can use its own SAML assertion
 * to request a "proxy" or "delegated" SAML assertion to present to a "downstream"
 * Web Service Provider (WSP) for authentication.</p>
 * <p>While this class implements the business logic for obtaining a delegated
 * SAML assertion, it is the {@link SAMLSession} class that is used to retain the
 * state of the authentication and the connection to the WSP.  Since this class
 * is not stateful, it can be considered thread-safe.</p>
 * 
 * @author Adam Rybicki
 */
public class SAMLDelegatedAuthenticationService {

  // XML namespace context
  private static final SAMLNamespaceContext NAMESPACE_CONTEXT = new SAMLNamespaceContext();
  private static final XPathExpressionPool EXPRESSION_POOL = new XPathExpressionPool(NAMESPACE_CONTEXT);
  
  protected final Logger logger = LoggerFactory.getLogger(this.getClass());
  
  private DOMImplementationLS domLoadSaveImpl = null;
  private static final String SOAP_PREFIX = "soap";
  
  /**
   * Public default constructor that performs basic initialization
   */
  public SAMLDelegatedAuthenticationService () {
    DOMImplementationRegistry registry;
    try {
      registry = DOMImplementationRegistry.newInstance();
      domLoadSaveImpl = (DOMImplementationLS)registry.getDOMImplementation("LS");
    }
    catch (ClassCastException ex) {
      logger.error("Unable to initialize XML serializer implementation.  Make sure that the correct jar files are present.", ex);
    }
    catch (ClassNotFoundException ex) {
      logger.error("Unable to initialize XML serializer implementation.  Make sure that the correct jar files are present.", ex);
    }
    catch (InstantiationException ex) {
      logger.error("Unable to initialize XML serializer implementation.  Make sure that the correct jar files are present.", ex);
    }
    catch (IllegalAccessException ex) {
      logger.error("Unable to initialize XML serializer implementation.  Make sure that the correct jar files are present.", ex);
    }
  }

  /**
   * <p>This method should be used to authenticate to and get a resource from
   * a Shibboleth-protected Web Service.  Because it establishes a SAML session,
   * this method is processing-intensive, as it makes several HTTP connections
   * to complete delegated authentication with the IdP.  Once the authentication
   * succeeds, the client of the library should use the HttpClient available
   * by calling {@link SAMLSession#getHttpClient()}</p>
   * 
   * <p>Calling this method should only be done in exceptional cases.  THis is
   * because the request and response interceptors installed on the HttpClient
   * by {@link SAMLSession} should be able to perform authentication
   * automatically.</p>
   * 
   * @param samlSession   SAML session
   * @param resource      a Resource object whose URL member is set to represent
   *                      the resource to retrieve.  Upon successful return the
   *                      Resource object will contain a String representing
   *                      the retrieved resource.  However, if this method returns
   *                      a non-null value, the returned value means should be used
   *                      to request the resource.
   * @return HttpResponse from the WSP after authentication.  Depending on the HTTP method used, this will
   *                      either include an HTTP 302 redirect to the originally requested resource or a result
   *                      of submitting form data in case if the initial request was from HTTP POST.
   */
  public HttpResponse authenticate(SAMLSession samlSession, Resource resource) {
    
    if (samlSession.getSamlAssertion() == null) {
      String message = "SAML assertion not present.";
      logger.error(message);
      throw new DelegatedAuthenticationRuntimeException(message);
    }
    if (samlSession.getPortalEntityID() == null) {
      String message = "Portal entity ID not present.";
      logger.error(message);
      throw new DelegatedAuthenticationRuntimeException(message);
    }
    DelegatedSAMLAuthenticationState authnState = new DelegatedSAMLAuthenticationState();
    // The following represents the entire delegated authentication flow
    if (getSOAPRequest(samlSession, resource, authnState) &&
        getIDP(samlSession, authnState) &&
        validateIDP(samlSession, authnState) &&
        processSOAPRequest(samlSession, authnState) &&
        getSOAPResponse(samlSession, authnState) &&
        processSOAPResponse(samlSession, authnState)) {
        
        HttpResponse response = sendSOAPResponse(samlSession, authnState);
        return response;
    }
      
    return null;
  }

  /**
   * <p>This method authenticates to a WPS as a result of intercepting a blocked
   * access for a resource and getting a SOAP request for delegated SAML
   * authentication.</p>
   * 
   * <p>This method is called by the {@link org.apache.http.HttpResponseInterceptor}
   * when the interceptor determines that the WSP requires authentication.</p>
   * 
   * @param samlSession SAML session
   * @param paosBytes SOAP request for authentication
   * @return HttpResponse from the WSP after authentication.  Depending on the HTTP method used, this will
   *                      either include an HTTP 302 redirect to the originally requested resource or a result
   *                      of submitting form data in case if the initial request was from HTTP POST.
   */
  public HttpResponse authenticate(SAMLSession samlSession, byte[] paosBytes) {
    if (samlSession.getSamlAssertion() == null) {
      String message = "SAML assertion not present.";
      logger.error(message);
      throw new DelegatedAuthenticationRuntimeException(message);
    }
    if (samlSession.getPortalEntityID() == null) {
      String message = "Portal entity ID not present.";
      logger.error(message);
      throw new DelegatedAuthenticationRuntimeException(message);
    }
    DelegatedSAMLAuthenticationState authnState = new DelegatedSAMLAuthenticationState();
    authnState.setSoapRequest(paosBytes);
    // The following represents the entire delegated authentication flow
    if (getIDP(samlSession, authnState) && 
        validateIDP(samlSession, authnState) && 
        processSOAPRequest(samlSession, authnState) && 
        getSOAPResponse(samlSession, authnState) && 
        processSOAPResponse(samlSession, authnState)) {
        
        HttpResponse response = sendSOAPResponse(samlSession, authnState);
        return response;
    }
    return null;
  }

  /**
   * This method makes a request for a resource, but assuming that the resource
   * is protected, it actually expects to receive a SOAP request for authentication.
   * This is referred to as a PAOS (reversed SOAP) request because the SOAP
   * request is returned as an http response. 
   * @param samlSession
   * @param resource
   * @param authnState
   * @return
   */
  private boolean getSOAPRequest(SAMLSession samlSession, Resource resource, DelegatedSAMLAuthenticationState authnState) {
    logger.debug("getSOAPRequest from {}", resource.getResourceUrl());
    HttpGet method = new HttpGet(resource.getResourceUrl());
    
    try {
      resource.setupWSPClientConnection(samlSession);
      // There is no need to check the HTTP response status because the HTTP
      // client will handle normal HTTP protocol flow, including redirects
      // In case of error, HTTP client will throw an exception
      HttpResponse response = samlSession.getHttpClient().execute(method);
      HttpEntity entity = response.getEntity();
      long contentLength = entity.getContentLength();
      ByteArrayOutputStream os = new ByteArrayOutputStream((int)contentLength);
      entity.writeTo(os);
      os.close();
      byte[] paosBytes = os.toByteArray();
      authnState.setSoapRequest(paosBytes);
    } catch (Exception ex) {
      // There is nothing that can be done about this exception other than to log it
      // Exception must be caught and not rethrown to allow normal processing to continue
      logger.error("Exception caught when trying to retrieve the resource.", ex);
      throw new DelegatedAuthenticationRuntimeException("Exception caught when trying to retrieve the resource.", ex);
    }
    return true;
  }

  /**
   * This method validates that the IDP in the SOAP request received from WSP
   * matches the one in the SAML assertion.
   * @param authnState 
   */
  private boolean validateIDP(SAMLSession samlSession, DelegatedSAMLAuthenticationState authnState) {
    InputStream is = null;
    
    try {
      is = new ByteArrayInputStream(authnState.getSoapRequest());
      InputSource source = new InputSource(is);
      DOMParser parser = new DOMParser();
      parser.setFeature("http://xml.org/sax/features/namespaces", true);
      parser.parse(source);
      Document doc = parser.getDocument();
      
      if (samlSession.isSkipValidateIdp()) {
          logger.debug("skipValidateIdp is set to true, setting soap request DOM");
          authnState.setSoapRequestDom(doc);
          return true;
      }
      
      String expression = "/S:Envelope/S:Header/ecp:Request/samlp:IDPList/samlp:IDPEntry[@ProviderID='" + authnState.getIdp() + "']";
      NodeList nodes = EXPRESSION_POOL.evaluate(expression, doc, XPathConstants.NODESET);

      if (nodes.getLength() > 0) {
        logger.debug("Found matching IDP using expression {}", expression);
        authnState.setSoapRequestDom(doc);
        return true;
      }
      logger.debug("No matching IDP found using expression {}", expression);
    }
    catch (XPathExpressionException ex) {
      logger.error("Programming error.  Invalid XPath expression.", ex);
      throw new DelegatedAuthenticationRuntimeException("Programming error.  Invalid XPath expression.", ex);
    }
    catch (SAXException ex) {
      logger.error("XML error.", ex);
      throw new DelegatedAuthenticationRuntimeException("XML error.", ex);
    }
    catch (IOException ex) {
      logger.error("Unexpected error.  This method performs no I/O!", ex);
      throw new DelegatedAuthenticationRuntimeException("Unexpected error.  This method performs no I/O!", ex);
    }
    finally {
      if(is != null) {
        try {
          is.close();
        }
        catch (IOException ex) {
          //safe to ignore during cleanup
        }
      }
    }
    return false;
  }

  /**
   * This method extracts the IDP from the SAML assertion
   * 
   * @param samlSession
   * @param authnState 
   * @return true, if successful
   */
  private boolean getIDP(SAMLSession samlSession, DelegatedSAMLAuthenticationState authnState) {
    InputStream is = null;
    try {
      if (samlSession.getSamlAssertionDom() == null) {
        is = new ByteArrayInputStream(samlSession.getSamlAssertion().getBytes());
        InputSource source = new InputSource(is);
        DOMParser parser = new DOMParser();
        parser.setFeature("http://xml.org/sax/features/namespaces", true);
        parser.parse(source);
        Document doc = parser.getDocument();
        samlSession.setSamlAssertionDom(doc);
      }
      String expression = "/saml2:Assertion/saml2:Issuer";
      Node node = EXPRESSION_POOL.evaluate(expression, samlSession.getSamlAssertionDom(), XPathConstants.NODE);
      
      if (node != null) {
        String idp = node.getTextContent();
        logger.debug("Found IDP {} using expression {}", idp, expression);
        authnState.setIdp(idp);
        
        if (samlSession.getIdpResolver() == null) {
          samlSession.setIdpResolver(new AssertionIdpResolverImpl(EXPRESSION_POOL));
        }
        
        samlSession.getIdpResolver().resolve(samlSession, authnState);
        return true;
      }
      
      logger.debug("No IDP found using expression {}", expression);
    }
    catch (XPathExpressionException ex) {
      logger.error("Programming error.  Invalid XPath expression.", ex);
      throw new DelegatedAuthenticationRuntimeException("Programming error.  Invalid XPath expression.", ex);
    }
    catch (SAXException ex) {
      logger.error("XML error.", ex);
      logger.trace("XML parsing error when parsing the SAML assertion.  The assertion was: [" + samlSession.getSamlAssertion() + "].");
      throw new DelegatedAuthenticationRuntimeException("XML error.", ex);
    }
    catch (IOException ex) {
      logger.error("Unexpected error.  This method performs no I/O!", ex);
      throw new DelegatedAuthenticationRuntimeException("Unexpected error.  This method performs no I/O!", ex);
    }
    finally {
      if(is != null) {
        try {
          is.close();
        }
        catch (IOException ex) {
          //safe to ignore during cleanup
        }
      }
    }
    return false;
  }

  /**
   * This method takes the SOAP request that come from the WSP and removes
   * the elements that need to be removed per the SAML Profiles spec.
   * 
   * @param samlSession
   * @param authnState 
   * @return true, if successful
   */
  private boolean processSOAPRequest(SAMLSession samlSession, DelegatedSAMLAuthenticationState authnState) {
    try {
      String expression = "/S:Envelope/S:Header/paos:Request";
      Document dom = authnState.getSoapRequestDom();
      Node node = EXPRESSION_POOL.evaluate(expression, dom, XPathConstants.NODE);
      
      if (node != null) {
        // Save the response consumer URL to samlSession
        String responseConsumerURL = node.getAttributes().getNamedItem("responseConsumerURL").getTextContent();
        logger.debug("Loaded response consumer URL {}", responseConsumerURL);
        authnState.setResponseConsumerURL(responseConsumerURL);
        // Save the PAOS MessageID, if present
        Node paosMessageID = node.getAttributes().getNamedItem("messageID");
        
        if (paosMessageID != null)
          authnState.setPaosMessageID(paosMessageID.getTextContent());
        else
          authnState.setPaosMessageID(null);

        // This removes the paos:Request node
        node.getParentNode().removeChild(node);

        // Retrieve the RelayState cookie for sending it back to the WSP with the SOAP Response
        expression = "/S:Envelope/S:Header/ecp:RelayState";
        node = EXPRESSION_POOL.evaluate(expression, dom, XPathConstants.NODE);
        Element relayStateElement = (Element)node;
        authnState.setRelayStateElement(relayStateElement);
        node.getParentNode().removeChild(node);
        
        // On to the ecp:Request for removal
        expression = "/S:Envelope/S:Header/ecp:Request";
        node = EXPRESSION_POOL.evaluate(expression, dom, XPathConstants.NODE);
        node.getParentNode().removeChild(node);
        
        // Now add some namespace bindings to the SOAP Header
        expression = "/S:Envelope/S:Header";
        Element soapHeader = EXPRESSION_POOL.evaluate(expression, dom, XPathConstants.NODE);
        
        // Add new elements to S:Header
        Element newElement = dom.createElementNS(NAMESPACE_CONTEXT.getNamespaceURI("sbf"), "sbf:Framework");
        newElement.setAttribute("version", "2.0");
        soapHeader.appendChild(newElement);
        newElement = dom.createElementNS(NAMESPACE_CONTEXT.getNamespaceURI("sb"), "sb:Sender");
        newElement.setAttribute("providerID", samlSession.getPortalEntityID());
        soapHeader.appendChild(newElement);
        newElement = dom.createElementNS(NAMESPACE_CONTEXT.getNamespaceURI("wsa"), "wsa:MessageID");
        String messageID = generateMessageID();
        newElement.setTextContent(messageID);
        soapHeader.appendChild(newElement);
        newElement = dom.createElementNS(NAMESPACE_CONTEXT.getNamespaceURI("wsa"), "wsa:Action");
        newElement.setTextContent("urn:liberty:ssos:2006-08:AuthnRequest");
        soapHeader.appendChild(newElement);
        
        // This is the wsse:Security element 
        Element securityElement = dom.createElementNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "wsse:Security");
        securityElement.setAttribute("S:mustUnderstand", "1");
        Element createdElement = dom.createElement("wsu:Created");
        // The examples use Zulu time zone, not local
        TimeZone zuluTimeZone = TimeZone.getTimeZone("Zulu"); 
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SS'Z'");
        sdf.setTimeZone(zuluTimeZone);
        createdElement.setTextContent(sdf.format(new Date()));
        newElement = dom.createElementNS("http://www.docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "wsu:Timestamp");
        newElement.appendChild(createdElement);
        securityElement.appendChild(newElement);
        // Finally, insert the original SAML assertion
        Node samlAssertionNode = dom.importNode(samlSession.getSamlAssertionDom().getDocumentElement(), true);
        securityElement.appendChild(samlAssertionNode);
        soapHeader.appendChild(securityElement);
        
        // Store the modified SOAP Request in the SAML Session
        String modifiedSOAPRequest = writeDomToString(dom);
        authnState.setModifiedSOAPRequest(modifiedSOAPRequest);
        logger.debug("Completed processing of SOAP request");
        return true;
      }
      logger.debug("Failed to process SOAP request using expression {}", expression);
    }
    catch (XPathExpressionException ex) {
      logger.error("Programming error.  Invalid XPath expression.", ex);
      throw new DelegatedAuthenticationRuntimeException("Programming error.  Invalid XPath expression.", ex);
    }
    return false;
  }

  /**
   * @return String containing a UUID
   */
  private String generateMessageID() {
    UUID uuid = UUID.randomUUID();
    String messageID = "urn:uuid:" + uuid.toString();
    return messageID;
  }

  /**
   * This method takes the SOAP AuthnRequest, sends it to the IdP, and retrieves
   * the result.  This method does not process the result.
   * 
   * @param samlSession SAML session
   * @param authnState 
   * @return true, if successful
   */
  private boolean getSOAPResponse(SAMLSession samlSession, DelegatedSAMLAuthenticationState authnState) {
    String result = null;
    HttpParams params = new BasicHttpParams();
    HttpProtocolParams.setVersion(params, HttpVersion.HTTP_1_1);
    HttpProtocolParams.setContentCharset(params, "UTF-8");
    params.setParameter("SOAPAction", "urn:liberty:ssos:2006-08:AuthnRequest");
    HttpClient client = new DefaultHttpClient (params);
    
    try {
      logger.debug("Getting SOAP response from {} with POST body:\n{}", authnState.getIdpEndpoint(), authnState.getModifiedSOAPRequest());
      setupIdPClientConnection(client, samlSession, authnState);
      HttpPost method = new HttpPost(authnState.getIdpEndpoint());
      StringEntity postData = new StringEntity(authnState.getModifiedSOAPRequest(), HTTP.UTF_8);
      method.setEntity(postData);
      HttpResponse httpResponse = client.execute(method);
      int resultCode = httpResponse.getStatusLine().getStatusCode();
      
      if (resultCode >= HttpStatus.SC_OK && resultCode < 300) {
        HttpEntity httpEntity = httpResponse.getEntity();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        httpEntity.writeTo(output);
        result = output.toString();
        logger.debug("Got SOAP response:\n{}", result);
        authnState.setSoapResponse(result);
        return true;
      }
      
      logger.error("Unsupported HTTP result code when retrieving the resource: " + resultCode + ".");
      throw new DelegatedAuthenticationRuntimeException("Unsupported HTTP result code when retrieving the resource: " + resultCode + ".");
    }
    catch (Exception ex) {
      logger.error("Exception caught when trying to retrieve the resource.", ex);
      throw new DelegatedAuthenticationRuntimeException("Exception caught when trying to retrieve the resource.", ex);
    } finally {
      client.getConnectionManager().shutdown();
    }
  }

  /**
   * This method processes the SOAP response from the IdP, and converts it
   * for presenting it back to the WSP that requested a delegated SAML
   * assertion.
   * 
   * @param samlSession SAML session
   * @param authnState 
   * @return true, if successful
   */
  private boolean processSOAPResponse(SAMLSession samlSession, DelegatedSAMLAuthenticationState authnState) {
    try {
      String expression = "/soap:Envelope/soap:Header/ecp:Response";
      InputStream is = new ByteArrayInputStream(authnState.getSoapResponse().getBytes());
      InputSource source = new InputSource(is);
      DOMParser parser = new DOMParser();
      parser.setFeature("http://xml.org/sax/features/namespaces", true);
      parser.parse(source);
      Document doc = parser.getDocument();
      Node node = EXPRESSION_POOL.evaluate(expression, doc, XPathConstants.NODE);
      
      if (node != null) {
        String responseConsumerURL = node.getAttributes().getNamedItem("AssertionConsumerServiceURL").getTextContent();
        
        logger.debug("Found {} node found in SOAP response.", expression);
        
        if (responseConsumerURL != null && responseConsumerURL.equals(authnState.getResponseConsumerURL())) {
          logger.debug("responseConsumerURL {} matches {}", responseConsumerURL, authnState.getResponseConsumerURL());
            
          // Retrieve and save the SOAP prefix used
          String soapPrefix = node.getParentNode().getPrefix();
          Element ecpResponse = (Element)node;
          Element soapHeader = (Element)ecpResponse.getParentNode();
          removeAllChildren(soapHeader);

          // Now on to the PAOS Response
          Element paosResponse = doc.createElementNS("urn:liberty:paos:2003-08", "paos:Response");
          paosResponse.setAttribute(soapPrefix + ":mustUnderstand", "1");
          paosResponse.setAttribute(soapPrefix + ":actor", "http://schemas.xmlsoap.org/soap/actor/next");
          
          // messageID is optional
          if (authnState.getPaosMessageID() != null)
            paosResponse.setAttribute("refToMessageID", authnState.getPaosMessageID());
          
          soapHeader.appendChild(paosResponse);
  
          if (authnState.getRelayStateElement() != null) {
            Node relayState = doc.importNode(authnState.getRelayStateElement(), true);
            soapHeader.appendChild(relayState);
          }

          // Store the modified SOAP Request in the SAML Session
          String modifiedSOAPResponse = writeDomToString(doc);
          authnState.setModifiedSOAPResponse(modifiedSOAPResponse);
          return true;
        }
        
        logger.debug("responseConsumerURL {} does not match {}", responseConsumerURL, authnState.getResponseConsumerURL());
        Document soapFaultMessage = createSOAPFaultDocument("AssertionConsumerServiceURL attribute missing or not matching the expected value.");
        Element soapHeader = (Element) soapFaultMessage.getFirstChild().getFirstChild();
        // Now on to the PAOS Response
        Element paosResponse = soapFaultMessage.createElementNS("urn:liberty:paos:2003-08", "paos:Response");
        paosResponse.setAttribute(SOAP_PREFIX + ":mustUnderstand", "1");
        paosResponse.setAttribute(SOAP_PREFIX + ":actor", "http://schemas.xmlsoap.org/soap/actor/next");
          
        // messageID is optional
        if (authnState.getPaosMessageID() != null) {
          paosResponse.setAttribute("refToMessageID", authnState.getPaosMessageID());
        }
          
        soapHeader.appendChild(paosResponse);
  
        if (authnState.getRelayStateElement() != null) {
          Node relayState = soapFaultMessage.importNode(authnState.getRelayStateElement(), true);
          soapHeader.appendChild(relayState);
        }
        // Store the SOAP Fault in the SAML Session
        String modifiedSOAPResponse = writeDomToString(soapFaultMessage);
        authnState.setModifiedSOAPResponse(modifiedSOAPResponse);
        sendSOAPFault(samlSession, authnState);
        return false;
        
      }
      
      // There was no response for the ECP.  Look for and propagate an error.
      String errorMessage = getSOAPFaultAsString(is);
        
      logger.warn("No {} node found in SOAP response. Error: {}", expression, errorMessage);
        
      if (errorMessage != null) {
        throw new DelegatedAuthenticationRuntimeException(errorMessage);
      }

      return false;
    }
    catch (XPathExpressionException ex) {
      logger.error("XPath programming error.", ex);
      throw new DelegatedAuthenticationRuntimeException("XPath programming error.", ex);
    }
    catch (SAXNotRecognizedException ex) {
      logger.error("Exception caught when trying to process the SOAP esponse from the IdP.", ex);
      throw new DelegatedAuthenticationRuntimeException("XPath programming error.", ex);
    }
    catch (SAXNotSupportedException ex) {
      logger.error("Exception caught when trying to process the SOAP esponse from the IdP.", ex);
      throw new DelegatedAuthenticationRuntimeException("Exception caught when trying to process the SOAP esponse from the IdP.", ex);
    }
    catch (SAXException ex) {
      logger.error("Exception caught when trying to process the SOAP esponse from the IdP.", ex);
      throw new DelegatedAuthenticationRuntimeException("Exception caught when trying to process the SOAP esponse from the IdP.", ex);
    }
    catch (DOMException ex) {
      logger.error("Exception caught when trying to process the SOAP esponse from the IdP.", ex);
      throw new DelegatedAuthenticationRuntimeException("Exception caught when trying to process the SOAP esponse from the IdP.", ex);
    }
    catch (IOException ex) {
      logger.error("This exception should not ever really occur, as the only I/O this method performs is on a ByteArrayInputStream.", ex);
      throw new DelegatedAuthenticationRuntimeException("This exception should not ever really occur, as the only I/O this method performs is on a ByteArrayInputStream.", ex);
    }
    catch (SOAPException ex) {
      logger.error("Error processing a SOAP message.", ex);
      throw new DelegatedAuthenticationRuntimeException("Error processing a SOAP message.", ex);
    }
  }

  /**
   * Utility method for serializing DOM to a String
   * @param doc Document to serialize
   * @return XML document as a String
   */
  private String writeDomToString(Document doc) {
    LSSerializer writer = domLoadSaveImpl.createLSSerializer();
    DOMConfiguration domConfig = writer.getDomConfig();
    domConfig.setParameter("xml-declaration", false);
    String xmlString = writer.writeToString(doc);
    return xmlString;
  }

  /**
   * Despite its name, this method performs two tasks:
   *    1)sending the SOAP response to the WSP is the final step of the delegated
   *      SAML authentication
   *    2)when this succeeds, the WSP returns the resource originally requested,
   *      so this also means that upon return from this method, the DelegatedSAMLAuthenticationState object
   *      will contain a String representation of the requested resource.
   *       
   * @param samlSession   SAML session representing this user and a SAML assertion
   *                      for the WSP on behalf of this user.
   * @param authnState      DelegatedSAMLAuthenticationState object that tracks the state of the authentication
   * @return HttpResponse from the WSP after authentication.  Depending on the HTTP method used, this will
   *                      either include an HTTP 302 redirect to the originally requested resource or a result
   *                      of submitting form data in case if the initial request was from HTTP POST.
   */
  private HttpResponse sendSOAPResponse(SAMLSession samlSession, DelegatedSAMLAuthenticationState authnState) {
    HttpPost method = new HttpPost(authnState.getResponseConsumerURL());
    method.setHeader("Content-Type", SAMLConstants.HTTP_HEADER_PAOS_CONTENT_TYPE);
    
    try {
      StringEntity postData = new StringEntity(authnState.getModifiedSOAPResponse(), HTTP.UTF_8);
      method.setEntity(postData);
      
      // Disable redirection
      HttpParams params = method.getParams();
      boolean redirecting = HttpClientParams.isRedirecting(params);
      if (redirecting) {
        HttpClientParams.setRedirecting(params, false);
        method.setParams(params);
      }
      HttpResponse response = samlSession.getHttpClient().execute(method);
      
      // Not sure whether this is necessary.  Just restoring HttpParams to
      // their original state.
      if (redirecting) {
        HttpClientParams.setRedirecting(params, true);
        method.setParams(params);
      }
      return response;
    } catch (Exception ex) {
      // There is nothing that can be done about this exception other than to log it
      // Exception must be caught and not rethrown to allow normal processing to continue
      logger.error("Exception caught when trying to retrieve the resource.", ex);
      throw new DelegatedAuthenticationRuntimeException("Exception caught while sending the delegated authentication assertion to the service provider.", ex);
    }
  }

  /**
   * This method sends the SOAP response to the WSP
   * without retrieving the result.  This method assumes that it is merely
   * communicating a failure to the WSP, and the SAMLSession contains the
   * failure message, a SOAP Fault
   * @param samlSession
   * @return true, if successful
   */
  private boolean sendSOAPFault(SAMLSession samlSession, DelegatedSAMLAuthenticationState authnState) {
    HttpPost method = new HttpPost(authnState.getResponseConsumerURL());
    method.setHeader("Content-Type", SAMLConstants.HTTP_HEADER_PAOS_CONTENT_TYPE);
    //method.setHeader("PAOS", SAMLConstants.HTTP_HEADER_PAOS);
    
    try {
      StringEntity postData = new StringEntity(authnState.getModifiedSOAPResponse(), HTTP.UTF_8);
      method.setEntity(postData);
      HttpResponse response = samlSession.getHttpClient().execute(method);
      response.getStatusLine().getStatusCode();
      return true;
    } catch (Exception ex) {
      // There is nothing that can be done about this exception other than to log it
      // Exception must be caught and not rethrown to allow normal processing to continue
      logger.error("Exception caught when trying to retrieve the resource.", ex);
      throw new DelegatedAuthenticationRuntimeException("Exception caught while sending the delegated authentication assertion to the service provider.", ex);
    }
  }

  /*
   * Empties the contents of an element
   */
  private void removeAllChildren(Element element) {
    Node child = element.getFirstChild();
    
    while (child != null) {
      Node next = child.getNextSibling(); 
      element.removeChild(child);
      child = next;
    }
  }
  
  /**
   * Assume that the InputStream has a SOAP fault message and return a String
   * suitable to present as an exception message
   *  
   * @param is InputStream that contains a SOAP message
   * @return String containing a formated error message
   * 
   * @throws IOException
   * @throws SOAPException
   */
  private String getSOAPFaultAsString(InputStream is) throws IOException, SOAPException {
    is.reset();
    MessageFactory factory = MessageFactory.newInstance();
    SOAPMessage message = factory.createMessage(null, is);
    SOAPBody body = message.getSOAPBody();
    
    if (body.hasFault()) {
      SOAPFault fault = body.getFault();
      String code, string, actor;
      code = fault.getFaultCode();
      string = fault.getFaultString();
      actor = fault.getFaultActor();
      String formatedMessage = "SOAP transaction resulted in a SOAP fault.";
      
      if (code != null)
        formatedMessage += "  Code=\"" + code + ".\"";
      
      if (string != null)
        formatedMessage += "  String=\"" + string + ".\"";
      
      if (actor != null)
        formatedMessage += "  Actor=\"" + actor + ".\"";
      
      return formatedMessage;
    }
    return null;
  }

  private Document createSOAPFaultDocument(String faultString) throws SOAPException {
    MessageFactory factory = MessageFactory.newInstance();
    SOAPMessage message = factory.createMessage();
    SOAPPart sp = message.getSOAPPart();
    SOAPEnvelope se = sp.getEnvelope();
    se.setPrefix(SOAP_PREFIX);
    se.getHeader().detachNode();
    se.addHeader();
    se.getBody().detachNode();
    SOAPBody body = se.addBody();
    SOAPFault fault = body.addFault();
    Name faultCode =  se.createName("Client", null,SOAPConstants.URI_NS_SOAP_ENVELOPE);
    fault.setFaultCode(faultCode);
    fault.setFaultString(faultString);
    return se.getOwnerDocument();
  }
  
  /**
   * Sets up the SSL parameters of a connection to the IdP, including the
   * client certificate and server certificate trust.  The program that set up
   * the SAMLSession object is responsible for providing these optional SSL
   * parameters.
   *  
   * @param client
   * @param samlSession
   * @param authnState 
   * @throws MalformedURLException 
   */
  private void setupIdPClientConnection(HttpClient client, SAMLSession samlSession, DelegatedSAMLAuthenticationState authnState) throws MalformedURLException {
    URL url = new URL(authnState.getIdpEndpoint());
    String protocol = url.getProtocol();
    int port = url.getPort();
    
    // Unless we are using SSL/TLS, there is no need to do the socket factory
    
    if (protocol.equalsIgnoreCase("https")) {
      SSLSocketFactory socketFactory = samlSession.getIdPSocketFactory();
      
      if (port == -1)
        port = 443;

      Scheme sch = new Scheme(protocol, socketFactory, port);
      client.getConnectionManager().getSchemeRegistry().unregister(protocol);
      client.getConnectionManager().getSchemeRegistry().register(sch);
    }
  }



}
