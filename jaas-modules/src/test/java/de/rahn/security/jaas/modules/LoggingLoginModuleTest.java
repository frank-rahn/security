package de.rahn.security.jaas.modules;

import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Einen manueller Login.
 * @author Frank W. Rahn
 */
public class LoggingLoginModuleTest {

	private LoginContext ctx;

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		System.setProperty("java.security.auth.login.config",
				"src/main/etc/jaas.config");

		ctx = new LoginContext("RahnLoggingLoginModule", new CallbackHandler() {
			@Override
			public void handle(Callback[] callbacks) {
				// nichts zu tun
			}
		});
	}

	/**
	 * @throws java.lang.Exception
	 */
	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testLogin() throws Exception {
		ctx.login();
		assertThat("Subject", ctx.getSubject(), notNullValue());
		ctx.logout();

		ctx.login();
		assertThat("Subject", ctx.getSubject(), notNullValue());
		ctx.logout();
	}

}
