package de.rahn.security.jaas.common;

import static org.apache.commons.lang3.Validate.notBlank;
import static org.apache.commons.lang3.builder.CompareToBuilder.reflectionCompare;
import static org.apache.commons.lang3.builder.EqualsBuilder.reflectionEquals;
import static org.apache.commons.lang3.builder.HashCodeBuilder.reflectionHashCode;
import static org.apache.commons.lang3.builder.ReflectionToStringBuilder.toStringExclude;

import java.io.Serializable;
import java.security.Principal;
import java.util.Collection;
import java.util.HashSet;

/**
 * Eine allgemeine Klasse für einen {@link Principal}.
 * @author Frank W. Rahn
 */
public abstract class AbstractPrincipal implements Principal, Serializable,
	Comparable<AbstractPrincipal> {

	/** serialVersionUID */
	private static final long serialVersionUID = 1L;

	/** Attribute, die zu excludieren sind. */
	protected static final Collection<String> EXCLUDE_FIELDS = new HashSet<>();

	static {
		EXCLUDE_FIELDS.add("password");
	}

	/** Der Name dieses {@link Principal}s. */
	private final String name;

	/**
	 * @param name der Name des {@link Principal}s
	 * @throws NullPointerException falls der Name <code>null</code> ist
	 * @throws IllegalArgumentException falls der Name nicht angegeben ist oder
	 *         nur aus Whitespaces besteht
	 */
	public AbstractPrincipal(String name) {
		super();

		notBlank(name, "Der Name (%s) des Principals muss gesetzt sein", name);

		this.name = name.trim();
	}

	/**
	 * {@inheritDoc}
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public final int compareTo(AbstractPrincipal other) {
		return reflectionCompare(this, other);
	}

	/**
	 * {@inheritDoc}
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public final boolean equals(Object obj) {
		return reflectionEquals(this, obj);
	}

	/**
	 * {@inheritDoc}
	 * @see java.security.Principal#getName()
	 */
	@Override
	public String getName() {
		return name;
	}

	/**
	 * {@inheritDoc}
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public final int hashCode() {
		return reflectionHashCode(this);
	}

	/**
	 * {@inheritDoc}
	 * @see java.lang.Object#toString()
	 */
	@Override
	public final String toString() {
		return toStringExclude(this, EXCLUDE_FIELDS);
	}

}