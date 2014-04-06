package de.rahn.security.jaas.modules;

import static de.rahn.security.jaas.common.SharedState.ROLES;
import static java.util.Collections.singleton;
import static org.apache.commons.lang3.StringUtils.trimToNull;

import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.spi.LoginModule;

/**
 * Ermittelt die Rolen des Benutzers. Hilfreich bei der Verwendung von
 * technischen Benutzern.
 * @author Frank W. Rahn
 */
public class RolesConfigVerifyModule implements LoginModule {

	/** Optionsname für die Rolle. */
	public static final String OPTIN_ROLE = "role";

	private Map<String, Object> sharedState;

	private Set<String> roles;

	/**
	 * {@inheritDoc}
	 * @see LoginModule#initialize(Subject, CallbackHandler, Map, Map)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler,
		Map<String, ?> sharedState, Map<String, ?> options) {

		this.sharedState = (Map<String, Object>) sharedState;

		String role = trimToNull((String) options.get(OPTIN_ROLE));
		if (role == null) {
			throw new IllegalArgumentException("Keine Rolle angegeben");
		}
		roles = singleton(role);
	}

	/**
	 * {@inheritDoc}
	 * @see LoginModule#login()
	 */
	@Override
	public boolean login() {
		sharedState.remove(ROLES.name());
		return true;
	}

	/**
	 * {@inheritDoc}
	 * @see javax.security.auth.spi.LoginModule#commit()
	 */
	@Override
	public boolean commit() {
		sharedState.put(ROLES.name(), roles);
		return true;
	}

	/**
	 * {@inheritDoc}
	 * @see javax.security.auth.spi.LoginModule#abort()
	 */
	@Override
	public boolean abort() {
		sharedState.remove(ROLES.name());
		return true;
	}

	/**
	 * {@inheritDoc}
	 * @see javax.security.auth.spi.LoginModule#logout()
	 */
	@Override
	public boolean logout() {
		sharedState.remove(ROLES.name());
		return true;
	}

}