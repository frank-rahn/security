package de.rahn.security.jaas.common;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThan;
import static org.hamcrest.Matchers.not;

import org.junit.Before;
import org.junit.Test;

/**
 * Test für die Klasse {@link AbstractPrincipal}.
 *
 * @author Frank W. Rahn
 */
public class AbstractPrincipalTest {

  private AbstractPrincipal test;
  private AbstractPrincipal lesser;
  private AbstractPrincipal equal;
  private AbstractPrincipal greater;

  @Before
  public void setUp() {
    test = new NewAbstractPrincipal("Frank");
    lesser = new NewAbstractPrincipal("Andreas");
    equal = new NewAbstractPrincipal("Frank");
    greater = new NewAbstractPrincipal("Xaver");
  }

  /** Test method for {@link AbstractPrincipal#hashCode()}. */
  @Test
  public void testHashCode() {
    assertThat(test.hashCode(), not(lesser.hashCode()));
    assertThat(test.hashCode(), is(equal.hashCode()));
    assertThat(test.hashCode(), not(greater.hashCode()));
    assertThat(lesser.hashCode(), not(greater.hashCode()));
  }

  /** Test method for {@link AbstractPrincipal#compareTo(AbstractPrincipal)} . */
  @Test
  public void testCompareTo() {
    assertThat(test.compareTo(lesser), greaterThan(0));
    assertThat(test.compareTo(equal), is(0));
    assertThat(test.compareTo(greater), lessThan(0));
    assertThat(lesser.compareTo(greater), lessThan(0));
  }

  /** Test method for {@link AbstractPrincipal#equals(Object)} . */
  @Test
  public void testEqualsObject() {
    assertThat(test, not(equalTo(lesser)));
    assertThat(test, equalTo(equal));
    assertThat(test, not(equalTo(greater)));
    assertThat(lesser, not(equalTo(greater)));
  }

  /** Test method for {@link AbstractPrincipal#getName()}. */
  @Test
  public void testGetName() {
    assertThat(test.getName(), is("Frank"));
  }

  /** Test method for {@link AbstractPrincipal#toString()}. */
  @Test
  public void testToString() {
    assertThat(test.toString(), containsString("Frank"));
    assertThat(test.toString(), not(containsString("geheim")));
  }

  private static class NewAbstractPrincipal extends AbstractPrincipal {

    private final String password;

    /** @see AbstractPrincipal */
    public NewAbstractPrincipal(String name) {
      super(name);

      password = "geheim";
    }

    /** @return the password */
    @SuppressWarnings("unused")
    public String getPassword() {
      return password;
    }
  }
}
