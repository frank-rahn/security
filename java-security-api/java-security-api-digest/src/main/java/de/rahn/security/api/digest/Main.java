package de.rahn.security.api.digest;

import static org.apache.commons.codec.binary.Base64.encodeBase64;

import de.rahn.security.api.SecurityPrinter;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/** @author Frank W. Rahn */
public class Main extends SecurityPrinter {

  public static void main(String[] args) {
    try (Main main = new Main()) {
      main.run();
    }
  }

  @Override
  public void run() {
    appendTitle("Message Digest mit SHA");

    try {
      MessageDigest digest_1 = MessageDigest.getInstance("SHA-1");
      appendDesc("Message Digest Info")
          .appendValue("Algorithm", digest_1.getAlgorithm())
          .appendValue("Digest-Length", digest_1.getDigestLength())
          .appendValue("Provider", digest_1.getProvider())
          .appendToString(digest_1)
          .appendln();

      MessageDigest digest_512 = MessageDigest.getInstance("SHA-512");
      appendDesc("Message Digest Info")
          .appendValue("Algorithm", digest_512.getAlgorithm())
          .appendValue("Digest-Length", digest_512.getDigestLength())
          .appendValue("Provider", digest_512.getProvider())
          .appendToString(digest_512)
          .appendln();

      ByteArrayOutputStream os = new ByteArrayOutputStream();
      os.write(TEXT.getBytes(StandardCharsets.UTF_8));

      digest_1.update(os.toByteArray());
      byte[] out = digest_1.digest();
      appendDesc("Kryptologische Hashfunktion SHA-1", 1)
          .appendValue("Text", TEXT)
          .appendValue("Hash (Raw)", out)
          .appendValue("Hash (Base64)", new String(encodeBase64(out)))
          .appendValue("Hash (Length)", out.length)
          .appendln();

      digest_512.update(os.toByteArray());
      out = digest_512.digest();
      appendDesc("Kryptologische Hashfunktion SHA-512")
          .appendValue("Text", TEXT)
          .appendValue("Hash (Raw)", out)
          .appendValue("Hash (Base64)", new String(encodeBase64(out)))
          .appendValue("Hash (Length)", out.length)
          .appendln();
    } catch (Exception exception) {
      append(exception);
    }
  }
}
