package utils;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

public class SymmetricEncryptor {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int IV_LENGTH_BYTES = 12; // Standard IV length for GCM
    private static final int TAG_LENGTH_BITS = 128; // Standard authentication tag length

    /**
     * Encrypts plaintext using AES/GCM with the given key.
     * Exceptions are handled internally and wrapped in a RuntimeException.
     *
     * @param plaintext The data to encrypt.
     * @param key The symmetric key (must be 16, 24, or 32 bytes for AES-128/192/256).
     * @return A byte array containing [IV + Ciphertext + AuthTag].
     */
    public static byte[] encrypt(byte[] plaintext, byte[] key) {
        try {
            byte[] iv = new byte[IV_LENGTH_BYTES];
            new SecureRandom().nextBytes(iv);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);

            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
            byte[] cipherText = cipher.doFinal(plaintext);

            ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + cipherText.length);
            byteBuffer.put(iv);
            byteBuffer.put(cipherText);
            return byteBuffer.array();
        } catch (GeneralSecurityException e) {
            // Encryption failures are often due to configuration errors (e.g., bad key length).
            // It's better to fail fast by throwing an unchecked exception.
            throw new RuntimeException("Error during AES encryption", e);
        }
    }

    /**
     * Decrypts AES/GCM ciphertext. Exceptions are handled internally.
     *
     * @param ivAndCipherText The byte array containing [IV + Ciphertext + AuthTag].
     * @param key The symmetric key used for encryption.
     * @return The original plaintext data, or null if decryption fails (e.g., wrong key, tampered data).
     */
    public static byte[] decrypt(byte[] ivAndCipherText, byte[] key) {
        try {
            ByteBuffer byteBuffer = ByteBuffer.wrap(ivAndCipherText);
            byte[] iv = new byte[IV_LENGTH_BYTES];
            byteBuffer.get(iv);
            byte[] cipherText = new byte[byteBuffer.remaining()];
            byteBuffer.get(cipherText);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);

            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);

            // GCM mode automatically verifies the authentication tag.
            // A BadPaddingException (specifically AEADBadTagException) is thrown if the tag is invalid.
            return cipher.doFinal(cipherText);
        } catch (GeneralSecurityException e) {
            // A decryption failure is an expected condition (e.g., wrong key, tampered data).
            // We return null to signal this failure without crashing.
            // For debugging, you might want to log the exception here.
             System.err.println("Decryption failed: " + e.getMessage());
            return null;
        }
    }
}