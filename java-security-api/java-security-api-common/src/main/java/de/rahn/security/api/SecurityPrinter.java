package de.rahn.security.api;

import static org.apache.commons.codec.binary.Hex.encodeHexString;
import static org.apache.commons.lang3.StringUtils.repeat;

import java.io.Closeable;
import java.io.Flushable;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * Diese Klasse soll Objekte der Java-Security-API bzw. der Java Cryptography
 * Extension (JCE) ausgeben.
 * @author Frank W. Rahn
 */
public abstract class SecurityPrinter implements Appendable, Closeable,
	Flushable, Runnable {

	private PrintWriter writer;

	/**
	 * Default Konstruktor
	 */
	public SecurityPrinter() {
		this(new PrintWriter(System.out));
	}

	/**
	 * Konstruktor.
	 * @param out ein Printwriter
	 */
	public SecurityPrinter(PrintWriter out) {
		writer = out;
	}

	/**
	 * @return the writer
	 */
	public final PrintWriter getWriter() {
		return writer;
	}

	/**
	 * {@inheritDoc}
	 * @see java.io.Flushable#flush()
	 */
	@Override
	public final void flush() throws IOException {
		writer.flush();
	}

	/**
	 * {@inheritDoc}
	 * @see java.io.Closeable#close()
	 */
	@Override
	public final void close() throws IOException {
		writer.close();
	}

	/**
	 * Gebe einen Zeilenumbruch aus.
	 * @return diesen Printer
	 */
	public SecurityPrinter appendln() {
		writer.println();
		return this;
	}

	/**
	 * {@inheritDoc}
	 * @see java.lang.Appendable#append(java.lang.CharSequence)
	 */
	@Override
	public SecurityPrinter append(CharSequence csq) {
		writer.append(csq);
		return this;
	}

	/**
	 * {@inheritDoc}
	 * @see java.lang.Appendable#append(java.lang.CharSequence, int, int)
	 */
	@Override
	public SecurityPrinter append(CharSequence csq, int start, int end) {
		writer.append(csq, start, end);
		return this;
	}

	/**
	 * {@inheritDoc}
	 * @see java.lang.Appendable#append(char)
	 */
	@Override
	public SecurityPrinter append(char c) {
		writer.append(c);
		return this;
	}

	/**
	 * Schreibe einen Hex-String.
	 * @param bytes die Bytes für den String
	 * @return diesen Printer
	 */
	public SecurityPrinter append(byte[] bytes) {
		writer.append("Hex = ");
		if (bytes == null) {
			writer.append("null");
		} else {
			writer.append(encodeHexString(bytes));
		}

		return this;
	}

	/**
	 * Schreibe einen Titel auf die Ausgabe.
	 * @param title
	 * @return diesen Printer
	 */
	public SecurityPrinter append(String title) {
		String filler = repeat("#", title.length() + 4);
		writer.append(filler).println();
		writer.append("# ").append(title).append(" #").println();
		writer.append(filler).println();
		writer.println();
		return this;
	}

}