package de.rahn.security.api.certificate;

import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import de.rahn.security.api.SecurityPrinter;

/**
 * @author Frank W. Rahn
 */
public class Main extends SecurityPrinter {

	/** Name der {@link KeyStore}-Datei. */
	protected static final String KEYSTORE = "target/keystore.jks";

	private CertificateHolder rootCACertificate;
	private CertificateHolder intermediateCACertificate;
	private CertificateHolder endEntityCertificate;

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
		appendTitle("Zertifikate und Java KeyStore (JKS)");

		try {
			X509Certificate certificate;

			// Den Provider registrieren
			Security.addProvider(new BouncyCastleProvider());

			// Leeren Java KeyStore anlegen
			KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			keyStore.load(null);
			appendDesc("Neuer KeyStore")
				.appendValue("DefaultType", KeyStore.getDefaultType())
				.appendValue("Type", keyStore.getType())
				.appendValue("Provider", keyStore.getProvider())
				.appendValue("Size (Entries)", keyStore.size())
				.appendValue("Aliase", keyStore.aliases())
				.appendValue("Classname", keyStore.getClass().getName())
				.appendToString(keyStore).appendln();

			// Fortlaufende Nummer erzeugen
			BigInteger serial = BigInteger.ONE;
			flush();

			// Erzeuge das Root CA Zertifikat
			rootCACertificate =
				new RootCertificateBuilder(keyStore, serial).build();
			certificate = rootCACertificate.getCertificate();

			appendDesc("Root CA Zertifikat")
				.appendValue("Type", certificate.getType())
				.appendValue("Encoded", certificate.getEncoded())
				.appendValue("Classname", certificate.getClass().getName())
				.appendToString(certificate).appendln();
			certificate.checkValidity(new Date());
			certificate.verify(certificate.getPublicKey());

			// Nächste fortlaufende Nummer erzeugen
			serial = serial.add(BigInteger.ONE);
			flush();

			// Erzeuge das Intermediate CA Zertifikat
			intermediateCACertificate =
				new IntermediateCertificateBuilder(keyStore, serial,
					rootCACertificate).build();
			certificate = intermediateCACertificate.getCertificate();

			appendDesc("Intermediate CA Zertifikat")
				.appendValue("Type", certificate.getType())
				.appendValue("Encoded", certificate.getEncoded())
				.appendValue("Classname", certificate.getClass().getName())
				.appendToString(certificate).appendln();
			certificate.checkValidity(new Date());
			certificate.verify(rootCACertificate.getKeyPair().getPublic());

			// Nächste fortlaufende Nummer erzeugen
			serial = serial.add(BigInteger.ONE);
			flush();

			// Erzeuge das End-Entity-Zertifikat
			endEntityCertificate =
				new EndEntityCertificateBuilder(keyStore, serial,
					intermediateCACertificate).build();
			certificate = endEntityCertificate.getCertificate();

			appendDesc("End Entity Zertifikat")
				.appendValue("Type", certificate.getType())
				.appendValue("Encoded", certificate.getEncoded())
				.appendValue("Classname", certificate.getClass().getName())
				.appendToString(certificate).appendln();
			certificate.checkValidity(new Date());
			certificate.verify(intermediateCACertificate.getKeyPair()
				.getPublic());

			flush();

			// Speichere Java KeyStore mit Passwort
			try (FileOutputStream output =
				new FileOutputStream(KEYSTORE, false)) {
				keyStore.store(output, PASSWORD.toCharArray());
			}
			boolean ok = new File(KEYSTORE).exists();
			appendDesc("Gespeicherter KeyStore").appendValue("Gespeicher", ok)
				.appendValue("Type", keyStore.getType())
				.appendValue("Provider", keyStore.getProvider())
				.appendValue("Size (Entries)", keyStore.size())
				.appendValue("Aliases", keyStore.aliases())
				.appendValue("Classname", keyStore.getClass().getName())
				.appendToString(keyStore).appendln();
		} catch (Exception exception) {
			append(exception);
		}
	}

}