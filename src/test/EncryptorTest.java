import org.junit.Assert;
import org.junit.Test;

import javax.crypto.AEADBadTagException;
import java.security.SecureRandom;
import java.util.Arrays;

public class EncryptorTest {

    private static final int AES_KEY_SIZE_BITS = 128;

    private static final byte[] PLAINTEXT = "The quick brown fox jumps over the lazy dog".getBytes();

    private static final byte[] AAD = "Testing. One, two, three.".getBytes();

    @Test
    public void testOk() {
        byte[] key = new byte[AES_KEY_SIZE_BITS / 8];
        new SecureRandom().nextBytes(key);

        Encryptor encryptor = new Encryptor(key);

        byte[] ciphertext = encryptor.encrypt(PLAINTEXT, AAD);
        byte[] decryptedPlaintext = encryptor.decrypt(ciphertext, AAD);

        Assert.assertTrue(Arrays.equals(PLAINTEXT, decryptedPlaintext));
    }

    @Test(expected = AEADBadTagException.class)
    public void testBadTag() {
        byte[] key = new byte[AES_KEY_SIZE_BITS / 8];
        new SecureRandom().nextBytes(key);

        Encryptor encryptor = new Encryptor(key);

        byte[] ciphertext = encryptor.encrypt(PLAINTEXT, AAD);
        ciphertext[ciphertext.length - 1] = (byte)(ciphertext[ciphertext.length - 1] + 1);
        encryptor.decrypt(ciphertext, AAD);
    }

    @Test(expected = AEADBadTagException.class)
    public void testBadAad() {
        byte[] key = new byte[AES_KEY_SIZE_BITS / 8];
        new SecureRandom().nextBytes(key);

        Encryptor encryptor = new Encryptor(key);

        byte[] ciphertext = encryptor.encrypt(PLAINTEXT, AAD);
        encryptor.decrypt(ciphertext, "Incorrect AAD".getBytes());
    }
}
