package org.jasig.portal.security.provider.saml;

/**
 * Created on Apr 23, 2009
 * @author Adam Rybicki
 */
public interface IdPEPRResolver {
  /**
   * This method will take the samlSession's idp entity ID and resolve it to
   * an endpoint.  The endpoint is a URL that the ECP will use to ask the IdP
   * for a delegated authentication assertion.  The endpoint will be placed into
   * authnState for later use.  This method is invoked immediately prior
   * to making a connection to the IdP.  The implementation of this method should
   * retrieve the IdP entityID, or name, by calling {@link SAMLSession#getIdp()}
   * and store the resolved endpoint by calling {@link DelegatedSAMLAuthenticationState#setIdpEndpoint(String) SAMLSession.setIdpEndpoint}.
   * 
   * @param samlSession SAMLSession instance
   * @param authnState DelegatedSAMLAuthenticationState instance to 
   */
  public void resolve(SAMLSession samlSession, DelegatedSAMLAuthenticationState authnState);
}
