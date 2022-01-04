package de.rahn.security.jaas.modules;

import static de.rahn.security.jaas.common.SharedState.ROLES;
import static de.rahn.security.jaas.common.SharedState.USERNAME;

import de.rahn.security.jaas.common.RolePrincipal;
import de.rahn.security.jaas.common.UserPrincipal;
import java.security.Principal;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.spi.LoginModule;

/**
 * Fasse die Ergebnisse der vorherigen {@link LoginModule} zusammen.
 *
 * @author Frank W. Rahn
 */
public class UserPasswordRolesVerifyModule implements LoginModule {

  private Subject subject;
  private Map<String, ?> sharedState;

  private final Set<Principal> principals = new HashSet<>();

  /** @see LoginModule#initialize(Subject, CallbackHandler, Map, Map) */
  @Override
  public void initialize(
      Subject subject,
      CallbackHandler callbackHandler,
      Map<String, ?> sharedState,
      Map<String, ?> options) {
    this.subject = subject;
    this.sharedState = sharedState;
  }

  /** @see LoginModule#login() */
  @Override
  public boolean login() {
    principals.clear();
    return true;
  }

  /** @see javax.security.auth.spi.LoginModule#commit() */
  @Override
  public boolean commit() {
    @SuppressWarnings("unchecked")
    Set<String> roles = (Set<String>) sharedState.get(ROLES.name());

    // Ermittle die Rollen (Optional)
    Set<RolePrincipal> rolesPrincipals = null;
    if (roles != null && !roles.isEmpty()) {
      rolesPrincipals = new HashSet<>();
      for (String role : roles) {
        rolesPrincipals.add(new RolePrincipal(role));
      }
      principals.addAll(rolesPrincipals);
    }

    // Ermittle den user (Required)
    String username = (String) sharedState.get(USERNAME.name());
    if (username == null) {
      principals.clear();
      return false;
    }
    principals.add(new UserPrincipal(username, rolesPrincipals));

    // Das Subject füllen
    return subject.getPrincipals().addAll(principals);
  }

  /** @see javax.security.auth.spi.LoginModule#abort() */
  @Override
  public boolean abort() {
    principals.clear();
    return true;
  }

  /** @see javax.security.auth.spi.LoginModule#logout() */
  @Override
  public boolean logout() {
    try {
      return subject.getPrincipals().removeAll(principals);
    } finally {
      principals.clear();
    }
  }
}
