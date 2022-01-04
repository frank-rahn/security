package de.rahn.security.api.certificate;

import static org.bouncycastle.asn1.x509.Extension.basicConstraints;
import static org.bouncycastle.asn1.x509.Extension.keyUsage;
import static org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier;
import static org.bouncycastle.asn1.x509.KeyUsage.cRLSign;
import static org.bouncycastle.asn1.x509.KeyUsage.keyCertSign;

import java.math.BigInteger;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;

/**
 * Erstelle ein Zertifikat einer Stammzertifizierungsstelle (Root CA).
 *
 * @author Frank W. Rahn
 */
public class RootCertificateBuilder extends CertificateBuilder {

  /** Der X.500-Name dieses Zertifikats. */
  private static final String X500NAME = "Root CA Certificate";

  /**
   * @param keyStore der {@link KeyStore} für das Zertifikat
   * @param serialNumber die fortlaufende Nummer dieses Zertifikates
   * @throws Exception, falls ein Fehler beim Erzeugen der Security-Objekte auftritt
   */
  public RootCertificateBuilder(KeyStore keyStore, BigInteger serialNumber) throws Exception {
    super(keyStore, serialNumber, X500NAME);
  }

  @Override
  protected X509Certificate buildCertificate() throws Exception {
    // Der X.500-Name des Zertifikatsausstellers
    X500Name issuer = buildX500Name(X500NAME).build();

    // Erzeuge ein X.509 v3 Zertifikatsgenerator
    X509v3CertificateBuilder builder = buildCertificateBuilder(issuer);

    // Füge die Extensions hinzu
    builder.addExtension(basicConstraints, true, new BasicConstraints(0));
    builder.addExtension(keyUsage, true, new KeyUsage(keyCertSign | cRLSign));
    builder.addExtension(
        subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier(keyPair.getPublic()));

    // Erstelle den Signatur-Algorithmus
    ContentSigner signer = buildContentSignerBuilder(keyPair.getPrivate());

    // Erstelle das selbst signierte Zertifikat
    return buildCertificate(builder.build(signer));
  }

  @Override
  public String getAlias() {
    return "root-ca";
  }
}
