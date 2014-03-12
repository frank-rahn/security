package de.rahn.security.api.encrypt.symmetric;

import static java.util.Arrays.asList;
import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

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

		try {
			for (String algorithm : asList("AES", "Blowfish")) {
				appendTitle("Symmetrische Verschlüsselung - Blockchiffre - "
					+ algorithm);

				// Generiere Schlüsselgenerator
				KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
				keyGenerator.init(new SecureRandom());
				appendDesc("Schlüsselgenerator", 1)
					.appendValue("Algorithm", keyGenerator.getAlgorithm())
					.appendValue("Provider", keyGenerator.getProvider())
					.appendValue("Classname", keyGenerator.getClass().getName())
					.appendToString(keyGenerator).appendln();

				// Generiere Schlüssel
				SecretKey key = keyGenerator.generateKey();
				appendDesc("Schlüssel")
					.appendValue("Algorithm", key.getAlgorithm())
					.appendValue("Format", key.getFormat())
					.appendValue("Encoded", key.getEncoded())
					.appendValue("Classname", key.getClass().getName())
					.appendToString(key).appendln();

				// Verschlüsselungsverfahren
				Cipher encrypt = Cipher.getInstance(algorithm);
				encrypt.init(ENCRYPT_MODE, key);
				appendDesc("Verschlüsselungsverfahren")
					.appendValue("Algorithm", encrypt.getAlgorithm())
					.appendValue("Provider", encrypt.getProvider())
					.appendValue("BlockSize", encrypt.getBlockSize())
					.appendValue("Parameters", encrypt.getParameters())
					.appendValue("IV", encrypt.getIV())
					.appendValue("ExemptionMechanism",
						encrypt.getExemptionMechanism())
					.appendValue("Classname", encrypt.getClass().getName())
					.appendToString(encrypt).appendln();

				// Verschlüsseln
				byte[] original = TEXT.getBytes("UTF-8");
				byte[] encryptBytes = encrypt.doFinal(original);
				appendDesc("Verschlüsselung")
					.appendValue("Input", TEXT)
					.appendValue("Input Length", TEXT_LENGTH)
					.appendValue("OutputSize",
						encrypt.getOutputSize(TEXT_LENGTH))
					.appendValue("Output", encryptBytes)
					.appendValue("Output Length", encryptBytes.length)
					.appendln();

				// Entschlüsselungsverfahren
				Cipher decode = Cipher.getInstance(algorithm);
				decode.init(DECRYPT_MODE, key);
				appendDesc("Entschlüsselungsverfahren")
					.appendValue("Algorithm", decode.getAlgorithm())
					.appendValue("Provider", decode.getProvider())
					.appendValue("BlockSize", decode.getBlockSize())
					.appendValue("Parameters", decode.getParameters())
					.appendValue("IV", decode.getIV())
					.appendValue("ExemptionMechanism",
						decode.getExemptionMechanism())
					.appendValue("Classname", decode.getClass().getName())
					.appendToString(decode).appendln();

				// Entchlüsseln
				byte[] decodeBytes = decode.doFinal(encryptBytes);
				appendDesc("Entschlüsselung:")
					.appendValue("Output", decodeBytes)
					.appendValue("Output Length", decodeBytes.length)
					.appendValue("Output Text",
						new String(decodeBytes, "UTF-8")).appendln();
			}
		} catch (Exception exception) {
			append(exception);
		}
	}

}
