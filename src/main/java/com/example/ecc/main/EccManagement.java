package com.example.ecc.main;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class EccManagement {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int GCM_IV_LENGTH_BYTES = 12;     // recommended for GCM
    private static final int GCM_TAG_LENGTH_BITS = 128;    // 16 bytes tag

    public static void main(String[] args) throws GeneralSecurityException {
        String plainText = "Hello World!";
        System.out.println("Plaintext: " + plainText);

        KeyPair keyPairA = generateKeyPair();
        KeyPair keyPairB = generateKeyPair();

        SecretKey secretKeyA = deriveAesKeyFromEcdh(keyPairA.getPrivate(), keyPairB.getPublic());
        SecretKey secretKeyB = deriveAesKeyFromEcdh(keyPairB.getPrivate(), keyPairA.getPublic());

        System.out.println("Secret Key A: " + Base64.getEncoder().encodeToString(secretKeyA.getEncoded()));
        System.out.println("Secret Key B: " + Base64.getEncoder().encodeToString(secretKeyB.getEncoded()));

        String encrypted = encryptString(secretKeyA, plainText);
        System.out.println("Encrypted text: " + encrypted);

        String decrypted = decryptString(secretKeyB, encrypted);
        System.out.println("Decrypted text: " + decrypted);
    }

    public static KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        // Bạn có thể đổi sang secp256r1 (phổ biến hơn) nếu muốn
        ECGenParameterSpec parameterSpec = new ECGenParameterSpec("secp192k1");
        keyPairGenerator.initialize(parameterSpec, SECURE_RANDOM);
        return keyPairGenerator.genKeyPair();
    }

    /** ECDH -> shared secret -> SHA-256 -> AES-256 key */
    public static SecretKey deriveAesKeyFromEcdh(PrivateKey privateKey, PublicKey publicKey)
            throws GeneralSecurityException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);

        byte[] sharedSecret = keyAgreement.generateSecret();
        byte[] keyMaterial = MessageDigest.getInstance("SHA-256").digest(sharedSecret); // 32 bytes
        return new SecretKeySpec(keyMaterial, "AES");
    }

    /**
     * Output format: Base64( IV(12) || CIPHERTEXT+TAG )
     */
    public static String encryptString(SecretKey key, String plainText) throws GeneralSecurityException {
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));

        byte[] ciphertextWithTag = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        byte[] out = ByteBuffer.allocate(iv.length + ciphertextWithTag.length)
                .put(iv)
                .put(ciphertextWithTag)
                .array();

        return Base64.getEncoder().encodeToString(out);
    }

    public static String decryptString(SecretKey key, String encrypted) throws GeneralSecurityException {
        byte[] in = Base64.getDecoder().decode(encrypted);

        if (in.length < GCM_IV_LENGTH_BYTES + 1) {
            throw new GeneralSecurityException("Invalid encrypted payload");
        }

        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        byte[] ciphertextWithTag = new byte[in.length - GCM_IV_LENGTH_BYTES];

        System.arraycopy(in, 0, iv, 0, GCM_IV_LENGTH_BYTES);
        System.arraycopy(in, GCM_IV_LENGTH_BYTES, ciphertextWithTag, 0, ciphertextWithTag.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));

        byte[] plaintext = cipher.doFinal(ciphertextWithTag);
        return new String(plaintext, StandardCharsets.UTF_8);
    }
}