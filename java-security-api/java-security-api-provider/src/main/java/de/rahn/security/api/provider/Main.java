package de.rahn.security.api.provider;

import java.security.Provider;
import java.security.Security;

import de.rahn.security.api.SecurityPrinter;

/**
 * @author Frank W. Rahn
 */
public class Main extends SecurityPrinter {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		try (Main main = new Main()) {
			main.run();
		}
	}

	/**
	 * {@inheritDoc}
	 * @see java.lang.Runnable#run()
	 */
	@Override
	public void run() {
		appendTitle("Die Liste der verfügbaren Security-Provider");

		for (Provider provider : Security.getProviders()) {
			appendDesc("Security Provider Info:")
				.appendValue("Name", provider.getName())
				.appendValue("Version", provider.getVersion())
				.appendValue("Info", provider.getInfo())
				.appendToString(provider);
		}
	}
}
