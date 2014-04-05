package de.rahn.security.jaas;

import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;

import javax.security.auth.login.LoginContext;

import org.junit.Before;
import org.junit.Test;

import de.rahn.security.jaas.handler.UserPasswordCallbackHandler;

/**
 * Einen manueller Login.
 * @author Frank W. Rahn
 */
public class UserPasswordLoginModuleTest {

	private LoginContext ctx;

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		System.setProperty("java.security.auth.login.config",
			"src/main/etc/jaas.config");

		ctx =
			new LoginContext("UserPasswordLoginModule",
					new UserPasswordCallbackHandler("tdb", "xxx"));
	}

	/**
	 * Führe ein Login und ein Logout durch.
	 * @throws Exception falls ein Fehler im Security-Module auftritt
	 */
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