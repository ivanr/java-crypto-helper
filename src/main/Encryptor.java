import lombok.NonNull;
import lombok.SneakyThrows;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

public class Encryptor {

    private static final byte VERSION_1 = 0x01;

    private static final int GCM_NONCE_LENGTH_BYTES = 12;

    private static final int GCM_TAG_LENGTH_BYTES = 16;

    private static final int MIN_CIPHERTEXT_LEN = 1 + 8 + 12 + 16;

    private static final int KEY_ID_LEN = 8;

    private final SecretKey key;

    private final byte[] keyId = new byte[KEY_ID_LEN];

    public Encryptor(byte[] keyBytes) {
        this.key = new SecretKeySpec(keyBytes, "AES");
        updateKeyId();
    }

    @SneakyThrows
    private void updateKeyId() {
        // We use only 8 bytes of the SHA256 hash as key identifier. The truncation
        // has no impact on security as the truncated hash is not used in any
        // cryptographic operations.
        System.arraycopy(
                MessageDigest.getInstance("SHA-256").digest(key.getEncoded()), 0,
                keyId, 0, KEY_ID_LEN);
    }

    @SneakyThrows
    public byte[] encrypt(@NonNull byte[] plaintext, @NonNull byte[] aad) {
        // Generate a cryptographically random nonce.
        final byte[] nonce = new byte[GCM_NONCE_LENGTH_BYTES];
        SecureRandom.getInstanceStrong().nextBytes(nonce);

        // Create cipher from key and nonce.
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BYTES * 8, nonce));

        // Encrypt; the output is ciphertext with a 12-byte tag appended to it
        cipher.updateAAD(aad);
        byte[] authenticatedCiphertext = cipher.doFinal(plaintext);

        // Combine everything together.
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(VERSION_1); // 1 byte
        baos.write(keyId); // 8 bytes
        baos.write(nonce); // 12 bytes
        baos.write(authenticatedCiphertext); // Length of plaintext + 16 bytes
        return baos.toByteArray();
    }

    @SneakyThrows
    public byte[] decrypt(@NonNull byte[] ciphertext, @NonNull byte[] aad) {
        if (ciphertext.length < MIN_CIPHERTEXT_LEN) {
            throw new IllegalArgumentException("invalid length");
        }

        if (ciphertext[0] != VERSION_1) {
            throw new IllegalArgumentException("invalid version: " + Integer.toHexString(ciphertext[0]));
        }

        if (!Arrays.equals(ciphertext, 1, 1 + KEY_ID_LEN, keyId, 0, KEY_ID_LEN)) {
            throw new IllegalArgumentException("invalid key");
        }

        // Get the nonce from the blob.
        final byte[] nonce = new byte[GCM_NONCE_LENGTH_BYTES];
        System.arraycopy(ciphertext, 1 + KEY_ID_LEN, nonce, 0, GCM_NONCE_LENGTH_BYTES);

        // Create cipher from key and nonce.
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BYTES * 8, nonce));

        // Decrypt.
        cipher.updateAAD(aad);
        return cipher.doFinal(ciphertext,
                1 + KEY_ID_LEN + GCM_NONCE_LENGTH_BYTES,
                ciphertext.length - 1 - KEY_ID_LEN - GCM_NONCE_LENGTH_BYTES);
    }
}
