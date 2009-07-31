package org.jasig.portal.security.provider.saml;

/**
 * RuntimeException to wrap exceptions encountered during delegated SAML
 * authentication processing.
 * 
 * @author Adam Rybicki
 */
public class DelegatedAuthenticationRuntimeException extends RuntimeException {

  private static final long serialVersionUID = -1161688435085160311L;

  /**
   * @param message Exception message
   * @param causedBy Wrapped exception
   * @see RuntimeException
   */
  public DelegatedAuthenticationRuntimeException(String message, Throwable causedBy) {
    super(message, causedBy);
  }

  /**
   * @see RuntimeException
   */
  public DelegatedAuthenticationRuntimeException() {
    super();
  }

  /**
   * @param message Exception message
   * @see RuntimeException
   */
  public DelegatedAuthenticationRuntimeException(String message) {
    super(message);
  }

  /**
   * @param causedBy Wrapped exception
   * @see RuntimeException
   */
  public DelegatedAuthenticationRuntimeException(Throwable causedBy) {
    super(causedBy);
  }

}
