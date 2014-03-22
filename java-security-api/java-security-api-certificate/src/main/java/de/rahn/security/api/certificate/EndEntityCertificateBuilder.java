package de.rahn.security.api.certificate;

import static org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier;
import static org.bouncycastle.asn1.x509.Extension.basicConstraints;
import static org.bouncycastle.asn1.x509.Extension.keyUsage;
import static org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier;
import static org.bouncycastle.asn1.x509.KeyUsage.digitalSignature;
import static org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment;

import java.math.BigInteger;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;

/**
 * @author Frank W. Rahn
 */
public class EndEntityCertificateBuilder extends CertificateBuilder {

	/** Der X.500-Name dieses Zertifikats. */
	private static final String X500NAME = "End Entity Certificate";

	private CertificateHolder certificateIssuer;

	/**
	 * @param keyStore der {@link KeyStore} für das Zertifikat
	 * @param serialNumber die fortlaufende Nummer dieses Zertifikates
	 * @param certificateIssuer das Zertifikat des Ausstellers
	 * @throws Exception falls ein Fehler beim Erzeugen der Security-Objekte
	 *         auftritt
	 */
	public EndEntityCertificateBuilder(KeyStore keyStore,
		BigInteger serialNumber, CertificateHolder certificateIssuer)
		throws Exception {
		super(keyStore, serialNumber, X500NAME);

		this.certificateIssuer = certificateIssuer;
	}

	/**
	 * {@inheritDoc}
	 * @see de.rahn.security.api.certificate.CertificateBuilder#buildCertificate()
	 */
	@Override
	protected X509Certificate buildCertificate() throws Exception {
		// Erzeuge ein X.509 v3 Zertifikatsgenerator
		X509v3CertificateBuilder builder =
			buildCertificateBuilder(certificateIssuer.getSubject());

		// Füge die Extensions hinzu
		builder.addExtension(basicConstraints, true,
			new BasicConstraints(false));
		builder.addExtension(keyUsage, true, new KeyUsage(digitalSignature
			| keyEncipherment));
		builder.addExtension(authorityKeyIdentifier, false, utils
			.createAuthorityKeyIdentifier(certificateIssuer.getKeyPair()
				.getPublic()));
		builder.addExtension(subjectKeyIdentifier, false,
			utils.createSubjectKeyIdentifier(keyPair.getPublic()));

		// Erstelle den Signaturalgorithmus
		ContentSigner signer =
			buildContentSignerBuilder(certificateIssuer.getKeyPair()
				.getPrivate());

		// Erstelle das Zertifikat
		return buildCertificate(builder.build(signer));
	}

	/**
	 * {@inheritDoc}
	 * @see de.rahn.security.api.certificate.CertificateHolder#getAlias()
	 */
	@Override
	public String getAlias() {
		return "end";
	}

}