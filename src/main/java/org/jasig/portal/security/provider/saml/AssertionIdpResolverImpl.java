package org.jasig.portal.security.provider.saml;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

/**
 * This class provides IdP ECP endpoint resolution based on the endpoint
 * reference (EPR) provided by Shibboleth IdP in the assertion.
 *
 * @author Adam Rybicki
 */
public class AssertionIdpResolverImpl implements IdPEPRResolver {

  // XML namespace context
  private SAMLNamespaceContext namespaceContext = new SAMLNamespaceContext();

  /* (non-Javadoc)
   * @see edu.uchicago.portal.portlets.samltest.domain.IdPEPRResolver#resolve(edu.uchicago.portal.portlets.samltest.domain.SAMLSession)
   */
  @Override
  public void resolve(SAMLSession samlSession, DelegatedSAMLAuthenticationState authnState) {
    /*
     *  This implementation will extract the EPR from the assertion per the
     *  following instructions from Scott Cantor.
     *  
     *  Find a <saml:AttributeStatement> and a <saml:Attribute> with the Name of
     *  "urn:liberty:ssos:2006-08".
     *  
     *  Verify the <disco:ServiceType> matches that URI as well.
     *  
     *  Verify the <disco:ProviderID> matches the expected IdP's entityID.
     *  
     *  Verify the <sbf:Framework> version is at least 2.0.
     *  
     *  The location to use will be in the <wsa:Address> element.
     *  
     *  Iterate over the <disco:SecurityContext> elements to find a context
     *  compatible with the client. This means finding a <disco:SecurityMechID> with
     *  an acceptable security mechanism, and that it either requires no security
     *  token (unlikely) or that the <sec:Token> has the appropriate usage attribute
     *  and references the enclosing assertion's ID.
     */
    XPathFactory xpFactory = XPathFactory.newInstance();
    XPath xpath = xpFactory.newXPath();
    xpath.setNamespaceContext(namespaceContext);
    String expression = "/saml2:Assertion/saml2:AttributeStatement/saml2:Attribute[@Name='urn:liberty:ssos:2006-08']";
    
    try {
      XPathExpression xpathExpression = xpath.compile(expression);
      Document doc = samlSession.getSamlAssertionDom();
      Node attributeNode = (Node)xpathExpression.evaluate (doc, XPathConstants.NODE);
      
      if (attributeNode == null) {
        throw new DelegatedAuthenticationRuntimeException("No saml2:Attribute containing IdP Endpoint Reference found in the SAML assertion.");
      }
      expression = "./saml2:AttributeValue/wsa:EndpointReference/wsa:Metadata[disco:ServiceType='urn:liberty:ssos:2006-08']";
      xpathExpression = xpath.compile(expression);
      Node serviceTypeNode = (Node)xpathExpression.evaluate (attributeNode, XPathConstants.NODE);
      
      if (serviceTypeNode == null) {
        throw new DelegatedAuthenticationRuntimeException("No matching ServiceType URI found in the Endpoint Reference");
      }
      expression = "./saml2:AttributeValue/wsa:EndpointReference/wsa:Metadata[disco:ProviderID='" + authnState.getIdp() + "']";
      xpathExpression = xpath.compile(expression);
      Node providerIDNode = (Node)xpathExpression.evaluate (attributeNode, XPathConstants.NODE);
      
      if (providerIDNode == null) {
        throw new DelegatedAuthenticationRuntimeException("Provider ID in the Endpoint Reference does not match the IdP previously established");
      }
      expression = "./saml2:AttributeValue/wsa:EndpointReference/wsa:Metadata/sbf:Framework[@version>=2.0]";
      xpathExpression = xpath.compile(expression);
      Node frameworkNode = (Node)xpathExpression.evaluate (attributeNode, XPathConstants.NODE);
      
      if (frameworkNode == null) {
        throw new DelegatedAuthenticationRuntimeException("Framework version must be at least 2.0");
      }
      expression = "./saml2:AttributeValue/wsa:EndpointReference/wsa:Address";
      xpathExpression = xpath.compile(expression);
      Node addressNode = (Node)xpathExpression.evaluate (attributeNode, XPathConstants.NODE);
      
      if (addressNode == null) {
        throw new DelegatedAuthenticationRuntimeException("Endpoint Reference Address node not present");
      }
      String ep = addressNode.getTextContent();
      authnState.setIdpEndpoint(ep);
    } catch (XPathExpressionException ex) {
      throw new DelegatedAuthenticationRuntimeException ("XPath processing error.", ex);
    }
  }

}

