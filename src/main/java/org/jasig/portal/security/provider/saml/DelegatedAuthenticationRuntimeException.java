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
