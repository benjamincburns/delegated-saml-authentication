package org.jasig.portal.security.provider.saml.spring;

import org.jasig.portal.security.provider.saml.DelegatedSAMLAuthenticationState;
import org.jasig.portal.security.provider.saml.IdPEPRResolver;
import org.jasig.portal.security.provider.saml.SAMLSession;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.metadata.MetadataManager;

public class SpringSAML2IdPEPRResolver implements IdPEPRResolver {
    private static final Logger logger = LoggerFactory.getLogger(SpringSAML2IdPEPRResolver.class);

    MetadataManager metadataManager;

    public SpringSAML2IdPEPRResolver(MetadataManager metadataManger){
        this.metadataManager = metadataManger;
    }

    @Override
    public void resolve(SAMLSession samlSession, DelegatedSAMLAuthenticationState authnState) {
        authnState.setIdpEndpoint("");
        String name = authnState.getIdp();
        EntityDescriptor descriptor = null;
        String entityId = null;
        try{
            descriptor = metadataManager.getEntityDescriptor(name);
            entityId = name;
        }catch(MetadataProviderException mpe){
            try{
                entityId = metadataManager.getEntityIdForAlias(name);
            }catch(MetadataProviderException mpe2){
                logger.warn("No IDP descriptor found for IDP name " + name);
            }
        }

        if(null != descriptor){
            IDPSSODescriptor idpssoDescriptor =
                    descriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
            for(SingleSignOnService sso : idpssoDescriptor.getSingleSignOnServices()){
                if(sso.getBinding().equals(SAMLConstants.SAML2_SOAP11_BINDING_URI)){
                    logger.debug("Set ECP client SSO endpoint to " + sso.getLocation());
                    authnState.setIdpEndpoint(sso.getLocation());
                    break;
                }
            }
        }
    }
}
