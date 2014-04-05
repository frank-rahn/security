package de.rahn.security.jaas.modules;

import static org.apache.commons.lang3.StringUtils.trimToNull;

import java.io.IOException;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.apache.commons.lang3.StringUtils;

import de.rahn.security.jaas.common.UserPrincipal;

/**
 * Prüfe Benutzername und Passwort gegen die LoginModule-Konfiguration.
 * Hilfreich bei der Verwendung von technischen Benutzern.
 * @author Frank W. Rahn
 */
public class UserPasswordConfigLoginModule implements LoginModule {

	/** Optionsname für den Benutzername. */
	public static final String OPTIN_USERNAME = "user";

	/** Optionsname fpr das Passwort. */
	public static final String OPTIN_PASSWORD = "password";

	private CallbackHandler callbackHandler;
	private Subject subject;
	private String username;
	private String password;

	private UserPrincipal principal;

	/**
	 * {@inheritDoc}
	 * @see LoginModule#initialize(Subject, CallbackHandler, Map, Map)
	 */
	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler,
		Map<String, ?> sharedState, Map<String, ?> options) {
		this.callbackHandler = callbackHandler;
		if (callbackHandler == null) {
			throw new IllegalArgumentException("callbackHandler ist null");
		}

		this.subject = subject;

		username = trimToNull((String) options.get(OPTIN_USERNAME));
		if (username == null) {
			throw new IllegalArgumentException("Kein Benutzername angegeben");
		}

		password = trimToNull((String) options.get(OPTIN_PASSWORD));
		if (password == null) {
			throw new IllegalArgumentException("Kein Passwort angegeben");
		}
	}

	/**
	 * {@inheritDoc}
	 * @see LoginModule#login()
	 */
	@Override
	public boolean login() throws LoginException {
		NameCallback nameCallback = new NameCallback("username:");
		PasswordCallback passwordCallback =
				new PasswordCallback("password:", false);

		try {
			callbackHandler.handle(new Callback[] { nameCallback,
				passwordCallback });
		} catch (IOException | UnsupportedCallbackException exception) {
			LoginException e =
					new LoginException(
							"Das Abrufen von Benutzername und Passwort ist fehlgeschlagen");
			e.initCause(exception);
			throw e;
		}

		// Prüfen von Benutzername und Passwort
		if (StringUtils.equals(username, nameCallback.getName())
				&& StringUtils.equals(password,
					new String(passwordCallback.getPassword()))) {
			principal = new UserPrincipal(username);
			return true;
		}
		return false;
	}

	/**
	 * {@inheritDoc}
	 * @see javax.security.auth.spi.LoginModule#commit()
	 */
	@Override
	public boolean commit() throws LoginException {
		if (principal != null) {
			return subject.getPrincipals().add(principal);
		}
		return false;
	}

	/**
	 * {@inheritDoc}
	 * @see javax.security.auth.spi.LoginModule#abort()
	 */
	@Override
	public boolean abort() throws LoginException {
		principal = null;
		return true;
	}

	/**
	 * {@inheritDoc}
	 * @see javax.security.auth.spi.LoginModule#logout()
	 */
	@Override
	public boolean logout() throws LoginException {
		try {
			return subject.getPrincipals().remove(principal);
		} finally {
			principal = null;
		}
	}

}