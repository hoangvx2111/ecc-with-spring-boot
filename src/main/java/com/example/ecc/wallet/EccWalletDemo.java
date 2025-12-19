package com.example.ecc.wallet;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class EccWalletDemo {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        // 1. Generate the ECC pair key with "secp256k1"
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
        keyGen.initialize(new ECGenParameterSpec("secp256k1"), new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        System.out.println("Private Key (Base64): " + Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        System.out.println("Public Key (Base64): " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));

        // 2. Create wallet address with SHA-256 and encode by Base64
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] pubKeyHash = sha256.digest(publicKey.getEncoded());
        String address = Base64.getEncoder().encodeToString(pubKeyHash);
        System.out.println("Wallet Address: " + address);

        // 3. Sign the wallet
        String txData = "Send 1 BTC to Alice";
        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaSign.initSign(privateKey);
        ecdsaSign.update(txData.getBytes());
        byte[] signature = ecdsaSign.sign();
        System.out.println("Signature (Base64): " + Base64.getEncoder().encodeToString(signature));

        // 4. Verify the wallet sign
        Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaVerify.initVerify(publicKey);
        ecdsaVerify.update(txData.getBytes());
        boolean isValid = ecdsaVerify.verify(signature);
        System.out.println("Signature valid? " + isValid);
    }
}
