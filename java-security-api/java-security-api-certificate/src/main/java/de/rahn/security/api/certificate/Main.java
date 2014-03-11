package de.rahn.security.api.certificate;

import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import de.rahn.security.api.SecurityPrinter;

/**
 * @author Frank W. Rahn
 */
public class Main extends SecurityPrinter {

	private static final String KEYSTORE = "keystore.jks";

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
			Security.addProvider(new BouncyCastleProvider());

			// Leeren Java KeyStore anlegen
			KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			keyStore.load(null);
			appendDesc("Neuer KeyStore")
				.appendValue("DefaultType", KeyStore.getDefaultType())
				.appendValue("Type", keyStore.getType())
				.appendValue("Provider", keyStore.getProvider())
				.appendValue("Size (Entries)", keyStore.size())
				.appendValue("Classname", keyStore.getClass().getName())
				.appendToString(keyStore).appendln();

			// http://www.java2s.com/Tutorial/Java/0490__Security/Catalog0490__Security.htm

			// Schlüsselpaar erzeugen
			KeyPairGenerator keyPairGenerator =
				KeyPairGenerator.getInstance("RSA", PROVIDER_NAME);
			keyPairGenerator.initialize(4096, new SecureRandom());
			KeyPair keyPair = keyPairGenerator.generateKeyPair();

			// Erzeuge X.500 Namen
			String hostname = InetAddress.getLocalHost().getHostName();
			X500NameBuilder nameBuilder =
				new X500NameBuilder().addRDN(BCStyle.CN, hostname)
					.addRDN(BCStyle.OU, "Frank W. Rahn")
					.addRDN(BCStyle.O, "Frank W. Rahn").addRDN(BCStyle.C, "DE");
			X500Name subjectName = nameBuilder.build();

			// Fortlaufende Nummer erzeugen
			BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

			// Zeiträume festlegen
			Date notBefore = new Date(System.currentTimeMillis() - 50000);
			Date notAfter = new Date(System.currentTimeMillis() + 50000);

			// Erzeuge ein X.509 Zertifikatgenerator
			X509v3CertificateBuilder certificateBuilder =
				new JcaX509v3CertificateBuilder(subjectName, serial, notBefore,
					notAfter, subjectName, keyPair.getPublic());

			// Erstelle den Signaturalgorithmus
			ContentSigner signatureAlgoithm =
				new JcaContentSignerBuilder("SHA256WithRSAEncryption")
					.setProvider(PROVIDER_NAME).build(keyPair.getPrivate());

			// Erstelle das selbstsignierte Zertifikat
			X509Certificate certificate =
				new JcaX509CertificateConverter()
					.setProvider(PROVIDER_NAME)
					.getCertificate(certificateBuilder.build(signatureAlgoithm));

			// Füge ein Zertifikat hinzu
			keyStore.setKeyEntry(hostname, keyPair.getPrivate(),
				PASSWORD.toCharArray(), new Certificate[] { certificate });

			// Basis Validierung
			certificate.checkValidity(new Date());
			certificate.verify(keyPair.getPublic());

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
				.appendValue("Classname", keyStore.getClass().getName())
				.appendToString(keyStore).appendln();
		} catch (Exception exception) {
			append(exception);
		}
	}

}