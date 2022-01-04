package de.rahn.security.jaas.common;

import javax.security.auth.spi.LoginModule;

/**
 * Konstanten für den SharedState eines {@link LoginModule}s.
 *
 * @author Frank W. Rahn
 */
public enum SharedState {
  USERNAME,
  ROLES
}
