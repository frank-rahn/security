package de.rahn.security.jaas;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;

import de.rahn.security.jaas.common.UserPrincipal;
import de.rahn.security.jaas.handler.UserPasswordCallbackHandler;
import javax.security.auth.login.LoginContext;
import org.junit.Before;
import org.junit.Test;

/**
 * Ein manueller Login.
 *
 * @author Frank W. Rahn
 */
public class UserPasswordLoginModuleTest {

  private LoginContext ctx;
  private UserPrincipal up;

  @Before
  public void setUp() throws Exception {
    System.setProperty("java.security.auth.login.config", "src/main/etc/jaas.config");

    ctx =
        new LoginContext("UserPasswordLoginModules", new UserPasswordCallbackHandler("tdb", "xxx"));

    up = new UserPrincipal("tdb");
  }

  /**
   * Führe ein Login und ein Logout durch.
   *
   * @throws Exception falls ein Fehler im Security-Module auftritt
   */
  @Test
  public void testLogin() throws Exception {
    ctx.login();
    assertThat("Subject", ctx.getSubject(), notNullValue());
    assertThat("UserPrincipal", ctx.getSubject().getPrincipals(), notNullValue());
    assertThat("UserPrincipal", ctx.getSubject().getPrincipals(), hasSize(1));
    assertThat("UserPrincipal", ctx.getSubject().getPrincipals(), hasItem(up));
    ctx.logout();

    ctx.login();
    assertThat("Subject", ctx.getSubject(), notNullValue());
    assertThat("UserPrincipal", ctx.getSubject().getPrincipals(), notNullValue());
    assertThat("UserPrincipal", ctx.getSubject().getPrincipals(), hasSize(1));
    assertThat("UserPrincipal", ctx.getSubject().getPrincipals(), hasItem(up));
    ctx.logout();
  }
}
