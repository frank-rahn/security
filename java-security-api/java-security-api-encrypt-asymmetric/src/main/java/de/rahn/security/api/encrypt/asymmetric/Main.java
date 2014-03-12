package de.rahn.security.api.encrypt.asymmetric;

import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.Cipher;

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
			final String algorithm = "RSA";

			appendTitle("Asymmetrische Verschlüsselung - " + algorithm);

			// Generiere Schlüsselgenerator
			KeyPairGenerator keyGenerator =
				KeyPairGenerator.getInstance(algorithm);
			keyGenerator.initialize(4096, new SecureRandom());
			appendDesc("Schlüsselgenerator")
				.appendValue("Algorithm", keyGenerator.getAlgorithm())
				.appendValue("Provider", keyGenerator.getProvider())
				.appendValue("Classname", keyGenerator.getClass().getName())
				.appendToString(keyGenerator).appendln();

			// Generiere Schlüsselpaar
			KeyPair keyPair = keyGenerator.generateKeyPair();

			// Hole öffentlichen Schlüssel
			PublicKey publicKey = keyPair.getPublic();
			appendDesc("Öffentlicher Schlüssel")
				.appendValue("Algorithm", publicKey.getAlgorithm())
				.appendValue("Format", publicKey.getFormat())
				.appendValue("Encoded", publicKey.getEncoded())
				.appendValue("Classname", publicKey.getClass().getName())
				.appendToString(publicKey).appendln();

			// Hole privaten Schlüssel
			PrivateKey privateKey = keyPair.getPrivate();
			appendDesc("Privater Schlüssel")
				.appendValue("Algorithm", privateKey.getAlgorithm())
				.appendValue("Format", privateKey.getFormat())
				.appendValue("Encoded", privateKey.getEncoded())
				.appendValue("Classname", privateKey.getClass().getName())
				.appendToString(privateKey).appendln();

			// Verschlüsselungsverfahren
			Cipher encrypt = Cipher.getInstance(algorithm);
			encrypt.init(ENCRYPT_MODE, publicKey);
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
			appendDesc("Verschlüsselung").appendValue("Input", TEXT)
				.appendValue("Input Length", TEXT_LENGTH)
				.appendValue("OutputSize", encrypt.getOutputSize(TEXT_LENGTH))
				.appendValue("Output", encryptBytes)
				.appendValue("Output Length", encryptBytes.length).appendln();

			// Entschlüsselungsverfahren
			Cipher decode = Cipher.getInstance(algorithm);
			decode.init(DECRYPT_MODE, privateKey);
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
			appendDesc("Entschlüsselung:").appendValue("Output", decodeBytes)
				.appendValue("Output Length", decodeBytes.length)
				.appendValue("Output Text", new String(decodeBytes, "UTF-8"))
				.appendln();
		} catch (Exception exception) {
			append(exception);
		}
	}

}