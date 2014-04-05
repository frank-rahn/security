package de.rahn.security.jaas.modules;

import java.util.Map;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

/**
 * @author Frank W. Rahn
 */
public class LoggingLoginModule implements LoginModule {

	private static final Logger LOGGER = Logger
		.getLogger(LoggingLoginModule.class.getName());

	private Subject subject;
	private CallbackHandler callbackHandler;
	private Map<String, ?> sharedState;
	private Map<String, ?> options;

	private String position = "<init>";

	/**
	 * Konstruktor.
	 */
	public LoggingLoginModule() {
		log("Constructor");
	}

	/**
	 * Log den aktuellen Schritt.
	 * @param method die akuelle Methode
	 * @return immer <code>true</code>
	 */
	private final boolean log(String method) {
		return log(method, false);
	}

	/**
	 * Log den aktuellen Schritt.
	 * @param method die akuelle Methode
	 * @return immer <code>true</code>
	 */
	private boolean log(String method, boolean withOptions) {
		StringBuilder stringBuilder =
			new StringBuilder("Login Module ").append(method)
				.append(" an der Position ").append(position)
				.append(" aufgerufen\n\tClass   ").append(getClass().getName())
				.append("\n\tSubject ").append(subject).append("\n\tStates  ")
				.append(sharedState);

		if (withOptions) {
			stringBuilder.append("\n\tHandler ").append(callbackHandler)
			.append("\n\tOptions ").append(options);
		}

		LOGGER.info(stringBuilder.toString());

		return true;
	}

	/**
	 * {@inheritDoc}
	 * @see LoginModule#initialize(Subject, CallbackHandler, Map, Map)
	 */
	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler,
		Map<String, ?> sharedState, Map<String, ?> options) {
		this.subject = subject;
		this.callbackHandler = callbackHandler;
		this.sharedState = sharedState;
		this.options = options;

		position = (String) options.get("position");

		log("initialize()", true);
	}

	/**
	 * {@inheritDoc}
	 * @see LoginModule#login()
	 */
	@Override
	public boolean login() throws LoginException {
		return log("login()");
	}

	/**
	 * {@inheritDoc}
	 * @see LoginModule#commit()
	 */
	@Override
	public boolean commit() throws LoginException {
		return log("commit()");
	}

	/**
	 * {@inheritDoc}
	 * @see LoginModule#abort()
	 */
	@Override
	public boolean abort() throws LoginException {
		return log("abort()");
	}

	/**
	 * {@inheritDoc}
	 * @see LoginModule#logout()
	 */
	@Override
	public boolean logout() throws LoginException {
		return log("logout()");
	}

}