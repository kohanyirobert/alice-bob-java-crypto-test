import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class Main {

  private static final DateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");

  public static void main(String[] args) throws Exception {
    byte[] message = send();
    intercept(message);
    receive(message);
  }

  private static byte[] send() throws Exception {
    KeyStore aliceKeyStore = getKeyStore("alice");

    Certificate aliceCertificate = aliceKeyStore.getCertificate("alice");
    @SuppressWarnings("unused")
    PublicKey alicePublicKey = aliceCertificate.getPublicKey();
    PrivateKey alicePrivateKey = (PrivateKey) aliceKeyStore.getKey("alice", "password".toCharArray());

    Certificate bobCertificate = aliceKeyStore.getCertificate("bob");
    ((X509Certificate) bobCertificate).checkValidity();
    PublicKey bobPublicKey = bobCertificate.getPublicKey();

    KeyGenerator sessionKeyGenerator = KeyGenerator.getInstance("AES");
    sessionKeyGenerator.init(256);

    SecretKey sessionSecretKey = sessionKeyGenerator.generateKey();

    Cipher keyCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    keyCipher.init(Cipher.ENCRYPT_MODE, sessionSecretKey);

    byte[] plaintextIv = keyCipher.getIV();
    byte[] plaintext = "Hello Bob! My name is Alice!".getBytes();
    byte[] plaintextCiphertext = keyCipher.doFinal(plaintext);

    Cipher keyPairCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    keyPairCipher.init(Cipher.ENCRYPT_MODE, bobPublicKey);

    byte[] sessionSecretKeyCiphertext = keyPairCipher.doFinal(sessionSecretKey.getEncoded());

    byte[] timestamp = toBytes(DATE_FORMAT.parse("2012-06-01 12:00:00").getTime());

    Mac mac = Mac.getInstance("HmacSHA512");
    mac.init(sessionSecretKey);
    mac.update(timestamp);
    mac.update(plaintext);

    byte[] messageAuthenticationCode = mac.doFinal();

    keyPairCipher.init(Cipher.ENCRYPT_MODE, alicePrivateKey);

    byte[] messageAuthenticationCodeCiphertext = keyPairCipher.doFinal(messageAuthenticationCode);

    System.out.format("Alice: %s, %s\n", new String(plaintext), new Date(fromBytes(timestamp)));

    return toBytes(toBytes(timestamp.length), timestamp,
        toBytes(messageAuthenticationCodeCiphertext.length), messageAuthenticationCodeCiphertext,
        toBytes(sessionSecretKeyCiphertext.length), sessionSecretKeyCiphertext,
        toBytes(plaintextIv.length), plaintextIv,
        toBytes(plaintextCiphertext.length), plaintextCiphertext);
  }

  private static void intercept(byte[] message) throws Exception {}

  private static void receive(byte[] message) throws Exception {
    // timestamp
    int from = 0;
    int to = 8;

    byte[] timestampLength = Arrays.copyOfRange(message, from, to);

    from = to;
    to += fromBytes(timestampLength);

    byte[] timestamp = Arrays.copyOfRange(message, from, to);

    // messageAuthenticationCodeCiphertext
    from = to;
    to += 8;

    byte[] messageAuthenticationCodeCiphertextLength = Arrays.copyOfRange(message, from, to);

    from = to;
    to += fromBytes(messageAuthenticationCodeCiphertextLength);

    byte[] messageAuthenticationCodeCiphertext = Arrays.copyOfRange(message, from, to);

    // secretKeyCiphertext
    from = to;
    to += 8;

    byte[] sessionSecretKeyCiphertextLength = Arrays.copyOfRange(message, from, to);

    from = to;
    to += fromBytes(sessionSecretKeyCiphertextLength);

    byte[] sessionSecretKeyCiphertext = Arrays.copyOfRange(message, from, to);

    // plaintextIv
    from = to;
    to += 8;

    byte[] plaintextIvLength = Arrays.copyOfRange(message, from, to);

    from = to;
    to += fromBytes(plaintextIvLength);

    byte[] plaintextIv = Arrays.copyOfRange(message, from, to);

    // plaintextCiphertext
    from = to;
    to += 8;

    byte[] plaintextCiphertextLength = Arrays.copyOfRange(message, from, to);

    from = to;
    to += fromBytes(plaintextCiphertextLength);

    byte[] plaintextCiphertext = Arrays.copyOfRange(message, from, to);

    KeyStore bobKeyStore = getKeyStore("bob");

    Certificate bobCertificate = bobKeyStore.getCertificate("bob");
    @SuppressWarnings("unused")
    PublicKey bobPublicKey = bobCertificate.getPublicKey();
    PrivateKey bobPrivateKey = (PrivateKey) bobKeyStore.getKey("bob", "password".toCharArray());

    Certificate aliceCertificate = bobKeyStore.getCertificate("alice");
    ((X509Certificate) aliceCertificate).checkValidity();
    PublicKey alicePublicKey = aliceCertificate.getPublicKey();

    Cipher keyPairCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    keyPairCipher.init(Cipher.DECRYPT_MODE, bobPrivateKey);

    SecretKey sessionSecretKey = new SecretKeySpec(keyPairCipher.doFinal(sessionSecretKeyCiphertext), "AES");

    Cipher keyCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    keyCipher.init(Cipher.DECRYPT_MODE, sessionSecretKey, new IvParameterSpec(plaintextIv));

    byte[] plaintext = keyCipher.doFinal(plaintextCiphertext);

    keyPairCipher.init(Cipher.DECRYPT_MODE, alicePublicKey);

    byte[] messageAuthenticationCode = keyPairCipher.doFinal(messageAuthenticationCodeCiphertext);

    Mac mac = Mac.getInstance("HmacSHA512");
    mac.init(sessionSecretKey);
    mac.update(timestamp);
    mac.update(plaintext);

    assert Arrays.equals(messageAuthenticationCode, mac.doFinal());

    System.out.format("Bob: %s, %s\n", new String(plaintext), new Date(fromBytes(timestamp)));
  }

  private static byte[] toBytes(long l) {
    return ByteBuffer.allocate(8).putLong(l).array();
  }

  private static long fromBytes(byte[] bytes) {
    assert bytes.length == 8;
    return ByteBuffer.wrap(bytes).getLong();
  }

  private static byte[] toBytes(byte[] bytes, byte[]... bytesArgs) {
    int length = bytes.length;
    for (byte[] bytesArg : bytesArgs)
      length += bytesArg.length;

    ByteBuffer buffer = ByteBuffer.allocate(length);
    buffer.put(bytes);
    for (byte[] bytesArg : bytesArgs)
      buffer.put(bytesArg);

    return buffer.array();
  }

  private static KeyStore getKeyStore(String name) throws Exception {
    KeyStore keyStore = KeyStore.getInstance("jks");
    try (InputStream inputStream = Main.class.getResourceAsStream(name + ".jks")) {
      keyStore.load(inputStream, "password".toCharArray());
    }
    return keyStore;
  }
}
