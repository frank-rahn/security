package de.rahn.security.api.certificate;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.x500.X500Name;

/**
 * Eine Schnittstelle für wichtigen Informationen rund um ein X.509-Zertifikate.
 *
 * @author Frank W. Rahn
 */
public interface CertificateHolder {

  /** @return eine Aliasname für das Zertifikat */
  String getAlias();

  /** @return das Zertifikat */
  X509Certificate getCertificate();

  /** @return der Zertifikatsinhaber nach X500 */
  X500Name getSubject();

  /** @return der Holder für das Schlüsselpaar */
  KeyPair getKeyPair();
}
