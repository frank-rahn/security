package de.rahn.security.jaas.common;

import static java.util.Collections.emptySet;
import static java.util.Collections.unmodifiableSet;

import java.security.Principal;
import java.util.Set;

/**
 * Der {@link Principal} für einen Benutzer.
 * @author Frank W. Rahn
 */
public class UserPrincipal extends AbstractPrincipal {

	/** serialVersionUID */
	private static final long serialVersionUID = 1L;

	private final Set<RolePrincipal> roles;

	/**
	 * @param name der Name eines Benutzers
	 * @param roles die Rollen des Benutzers, kann <code>null</code> sein
	 */
	public UserPrincipal(String name, Set<RolePrincipal> roles) {
		super(name);

		if (roles == null) {
			this.roles = emptySet();
		} else {
			this.roles = unmodifiableSet(roles);
		}
	}

	/**
	 * @return die Rollen des Benutzers oder eine leere Liste
	 */
	public Set<RolePrincipal> getRoles() {
		return roles;
	}

}