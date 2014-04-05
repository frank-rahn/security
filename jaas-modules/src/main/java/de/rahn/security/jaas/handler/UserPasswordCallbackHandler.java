package de.rahn.security.jaas.handler;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 * Ein {@link CallbackHandler} für technische Benutzer.
 * @author Frank W. Rahn
 */
public class UserPasswordCallbackHandler implements CallbackHandler {

	private String username;
	private String password;

	/**
	 *
	 */
	public UserPasswordCallbackHandler(String username, String password) {
		this.username = username;
		this.password = password;
	}

	/**
	 * {@inheritDoc}
	 * @see CallbackHandler#handle(Callback[])
	 */
	@Override
	public void handle(Callback[] callbacks)
			throws UnsupportedCallbackException {
		for (Callback callback : callbacks) {
			if (callback instanceof NameCallback) {
				((NameCallback) callback).setName(username);
			} else if (callback instanceof PasswordCallback) {
				((PasswordCallback) callback).setPassword(password
					.toCharArray());
			} else {
				throw new UnsupportedCallbackException(callback,
						"Dieser Callback wird nicht unterstützt.");
			}
		}
	}

}