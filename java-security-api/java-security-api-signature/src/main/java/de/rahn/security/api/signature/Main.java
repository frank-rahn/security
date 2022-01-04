package de.rahn.security.api.signature;

import de.rahn.security.api.SecurityPrinter;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

/** @author Frank W. Rahn */
public class Main extends SecurityPrinter {

  public static void main(String[] args) {
    try (Main main = new Main()) {
      main.run();
    }
  }

  @Override
  public void run() {

    try {
      appendTitle("Signieren");

      // Generiere Schlüsselgenerator
      KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
      keyGenerator.initialize(4096, new SecureRandom());
      appendDesc("Schlüsselgenerator", 1)
          .appendValue("Algorithm", keyGenerator.getAlgorithm())
          .appendValue("Provider", keyGenerator.getProvider())
          .appendValue("Classname", keyGenerator.getClass().getName())
          .appendToString(keyGenerator)
          .appendln();

      // Generiere Schlüsselpaar
      KeyPair keyPair = keyGenerator.generateKeyPair();

      // Hole öffentlichen Schlüssel
      PublicKey publicKey = keyPair.getPublic();
      appendDesc("Öffentlicher Schlüssel")
          .appendValue("Algorithm", publicKey.getAlgorithm())
          .appendValue("Format", publicKey.getFormat())
          .appendValue("Encoded", publicKey.getEncoded())
          .appendValue("Classname", publicKey.getClass().getName())
          .appendToString(publicKey)
          .appendln();

      // Hole privaten Schlüssel
      PrivateKey privateKey = keyPair.getPrivate();
      appendDesc("Privater Schlüssel")
          .appendValue("Algorithm", privateKey.getAlgorithm())
          .appendValue("Format", privateKey.getFormat())
          .appendValue("Encoded", privateKey.getEncoded())
          .appendValue("Classname", privateKey.getClass().getName())
          .appendToString(privateKey)
          .appendln();

      // Erzeugung einer Signatur zum Unterschreiben
      Signature signer = Signature.getInstance("SHA512withRSA");
      signer.initSign(privateKey);
      appendDesc("Signatur zum Unterschreiben")
          .appendValue("Algorithm", signer.getAlgorithm())
          .appendValue("Provider", signer.getProvider())
          .appendValue("Classname", signer.getClass().getName())
          .appendToString(signer)
          .appendln();

      // Unterschreiben
      byte[] original = TEXT.getBytes(StandardCharsets.UTF_8);
      signer.update(original);
      byte[] signatureBytes = signer.sign();
      appendDesc("Signatur")
          .appendValue("Input", TEXT)
          .appendValue("Input Length", TEXT_LENGTH)
          .appendValue("Output", signatureBytes)
          .appendValue("Output Length", signatureBytes.length)
          .appendln();

      // Erzeugung einer Signatur zum Überprüfen
      Signature verifier = Signature.getInstance("SHA512withRSA");
      verifier.initVerify(publicKey);
      appendDesc("Signatur zum Überprüfen")
          .appendValue("Algorithm", verifier.getAlgorithm())
          .appendValue("Provider", verifier.getProvider())
          .appendValue("Classname", verifier.getClass().getName())
          .appendToString(verifier)
          .appendln();

      // Überprüfen
      verifier.update(original);
      boolean ok = verifier.verify(signatureBytes);
      appendDesc("Überprüfen").appendValue("Ergebnis", ok).appendln();
    } catch (Exception exception) {
      append(exception);
    }
  }
}
