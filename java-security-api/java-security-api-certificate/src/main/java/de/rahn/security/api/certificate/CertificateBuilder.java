package de.rahn.security.api.certificate;

import static de.rahn.security.api.SecurityPrinter.PASSWORD;
import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Die Gemeinsamkeit für alle Zertifikat-Ersteller.
 * @author Frank W. Rahn
 */
public abstract class CertificateBuilder implements CertificateHolder {

	/** Gültigkeit 1 Tag. */
	protected static final int VALIDITY = 24 * 60 * 60 * 1000;

	protected X509Certificate certificate;
	protected X500Name subject;
	protected KeyPair keyPair;
	protected KeyStore keyStore;
	protected BigInteger serialNumber;
	protected Date notBefore;
	protected Date notAfter;
	protected JcaX509ExtensionUtils utils;

	/**
	 * @param keyStore der {@link KeyStore} für das Zertifikat
	 * @param serialNumber die fortlaufende Nummer dieses Zertifikates
	 * @param cn der "Common Name" des Zertifikatinhabers
	 * @throws Exception falls ein Fehler beim Erzeugen der Security-Objekte
	 *         auftritt
	 */
	public CertificateBuilder(KeyStore keyStore, BigInteger serialNumber,
		String cn) throws Exception {
		super();

		this.keyStore = keyStore;
		this.serialNumber = serialNumber;

		// Erzeuge die benötigten Utilities
		notBefore = new Date(System.currentTimeMillis());
		notAfter = new Date(System.currentTimeMillis() + VALIDITY);
		utils = new JcaX509ExtensionUtils();

		// Erzeuge die Security-Objekte
		keyPair = buildKeyPair();
		subject = buildX500Name(cn).build();
	}

	/**
	 * Erstelle das Zertifikat.
	 * @throws Exception falls ein Fehler beim Erzeugen der Security-Objekte
	 *         auftritt
	 */
	public CertificateHolder build() throws Exception {
		// Erstelle das Zertifikat
		certificate = buildCertificate();

		// Speichere das Zertifikat im KeyStore
		keyStore.setKeyEntry(getAlias(), keyPair.getPrivate(),
			PASSWORD.toCharArray(), new Certificate[] { certificate });

		return this;
	}

	/**
	 * Erstelle das Schlüsselpaar.
	 * @throws GeneralSecurityException falls ein Fehler beim Erzeugen der
	 *         Security-Objekte auftritt
	 */
	protected KeyPair buildKeyPair() throws GeneralSecurityException {
		// Schlüsselgenerator erzeugen
		KeyPairGenerator generator =
			KeyPairGenerator.getInstance("RSA", PROVIDER_NAME);
		generator.initialize(4096, new SecureRandom());

		// Schlüsselpaar erzeugen
		return generator.generateKeyPair();
	}

	/**
	 * Erstelle einen X.500-Namen.
	 * @param cn der "Common Name"
	 */
	protected X500NameBuilder buildX500Name(String cn) {
		return new X500NameBuilder().addRDN(BCStyle.CN, cn)
			.addRDN(BCStyle.O, "Frank W. Rahn").addRDN(BCStyle.C, "DE");
	}

	/**
	 * Erstelle das Zertifikat.
	 * @throws Exception falls ein Fehler beim Erzeugen der Security-Objekte
	 *         auftritt
	 */
	protected abstract X509Certificate buildCertificate() throws Exception;

	/**
	 * Erstelle das X.509-Zertifikat aus dem {@link X509CertificateHolder}.
	 * @param holder der {@link X509CertificateHolder}
	 * @throws GeneralSecurityException falls ein Fehler beim Erzeugen der
	 *         Security-Objekte auftritt
	 */
	protected X509Certificate buildCertificate(X509CertificateHolder holder)
		throws GeneralSecurityException {
		return new JcaX509CertificateConverter().setProvider(PROVIDER_NAME)
			.getCertificate(holder);
	}

	/**
	 * Erzeuge ein X.509 v3 Zertifikatsgenerator.
	 * @param issuer der Zertifikatsaussteller
	 * @return der X.509 v3 Zertifikatsgenerator
	 */
	protected JcaX509v3CertificateBuilder buildCertificateBuilder(
		X500Name issuer) {
		return new JcaX509v3CertificateBuilder(issuer, serialNumber, notBefore,
			notAfter, subject, keyPair.getPublic());
	}

	/**
	 * Erzeuge den Unterzeichner des Zertifikatsausstellers.
	 * @param privateKey der private Schlüssel des Zertifikatsausstellers.
	 * @return der Unterzeichner
	 * @throws OperatorException falls der Unterzeichner nicht erstellt werden
	 *         kann
	 */
	protected ContentSigner buildContentSignerBuilder(PrivateKey privateKey)
		throws OperatorException {
		return new JcaContentSignerBuilder("SHA256WithRSAEncryption")
			.setProvider(PROVIDER_NAME).build(privateKey);
	}

	/**
	 * {@inheritDoc}
	 * @see de.rahn.security.api.certificate.CertificateHolder#getCertificate()
	 */
	@Override
	public X509Certificate getCertificate() {
		return certificate;
	}

	/**
	 * {@inheritDoc}
	 * @see de.rahn.security.api.certificate.CertificateHolder#getSubject()
	 */
	@Override
	public X500Name getSubject() {
		return subject;
	}

	/**
	 * {@inheritDoc}
	 * @see de.rahn.security.api.certificate.CertificateHolder#getKeyPair()
	 */
	@Override
	public KeyPair getKeyPair() {
		return keyPair;
	}

}
