package org.jasig.portal.security.provider.saml;

/**
 * Exception to wrap exceptions encountered during delegated SAML
 * authentication processing.
 * 
 * @author Adam Rybicki
 */
public class DelegatedAuthenticationException extends Exception {

  private static final long serialVersionUID = 1L;

  /**
   * @param message Exception message
   * @param causedBy Wrapped exception
   * @see Exception
   */
  public DelegatedAuthenticationException(String message, Throwable causedBy) {
    super(message, causedBy);
  }

  /**
   * @see Exception
   */
  public DelegatedAuthenticationException() {
    super();
  }

  /**
   * @param message Exception message
   * @see Exception
   */
  public DelegatedAuthenticationException(String message) {
    super(message);
  }

  /**
   * @param causedBy Wrapped exception
   * @see Exception
   */
  public DelegatedAuthenticationException(Throwable causedBy) {
    super(causedBy);
  }

}
