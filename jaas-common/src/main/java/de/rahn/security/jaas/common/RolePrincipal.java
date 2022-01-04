package de.rahn.security.jaas.common;

import java.security.Principal;

/**
 * Der {@link Principal} für eine Rolle.
 *
 * @author Frank W. Rahn
 */
public class RolePrincipal extends AbstractPrincipal {

  /** serialVersionUID */
  private static final long serialVersionUID = 1L;

  /** @param name der Name der Rolle */
  public RolePrincipal(String name) {
    super(name);
  }
}
