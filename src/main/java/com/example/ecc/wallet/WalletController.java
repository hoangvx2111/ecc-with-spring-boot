package com.example.ecc.wallet;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.web.bind.annotation.*;
import javax.annotation.PostConstruct;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Base64;

@RestController
@RequestMapping("/wallet")
public class WalletController {
    private final Map<String, KeyPair> walletStore = new ConcurrentHashMap<>();

    @PostConstruct
    public void setupProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }

    // 1. Create a wallet
    @PostMapping("/create")
    public Map<String, String> createWallet() throws Exception {
        // Create a key pair with "secp256k1"
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
        keyGen.initialize(new ECGenParameterSpec("secp256k1"), new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        //Create a wallet address with SHA-256 and encode by Base64
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] pubKeyHash = sha256.digest(keyPair.getPublic().getEncoded());
        String address = Base64.getEncoder().encodeToString(pubKeyHash);

        //Put the wallet to store
        walletStore.put(address, keyPair);

        Map<String, String> result = new HashMap<>();
        result.put("address", address);
        result.put("publicKey", Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        return result;
    }

    // 2. List all wallet
    @GetMapping("/list")
    public List<Map<String, String>> listWallets() {
        List<Map<String, String>> result = new ArrayList<>();
        for (Map.Entry<String, KeyPair> entry : walletStore.entrySet()) {
            Map<String, String> wallet = new HashMap<>();
            wallet.put("address", entry.getKey());
            wallet.put("publicKey", Base64.getEncoder().encodeToString(entry.getValue().getPublic().getEncoded()));
            result.add(wallet);
        }
        return result;
    }

    // 3. Create wallet sign
    @PostMapping("/sign")
    public Map<String, String> signData(@RequestBody Map<String, String> req) throws Exception {
        String address = req.get("address");
        String data = req.get("data");
        KeyPair keyPair = walletStore.get(address);
        if (keyPair == null) throw new IllegalArgumentException("Wallet not found");

        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaSign.initSign(keyPair.getPrivate());
        ecdsaSign.update(data.getBytes());
        byte[] signature = ecdsaSign.sign();

        Map<String, String> result = new HashMap<>();
        result.put("signature", Base64.getEncoder().encodeToString(signature));
        return result;
    }

    // 4. Wallet sign verify
    @PostMapping("/verify")
    public Map<String, Object> verifySignature(@RequestBody Map<String, String> req) throws Exception {
        String address = req.get("address");
        String data = req.get("data");
        String signatureB64 = req.get("signature");
        KeyPair keyPair = walletStore.get(address);
        if (keyPair == null) throw new IllegalArgumentException("Wallet not found");

        Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaVerify.initVerify(keyPair.getPublic());
        ecdsaVerify.update(data.getBytes());
        boolean valid = ecdsaVerify.verify(Base64.getDecoder().decode(signatureB64));

        Map<String, Object> result = new HashMap<>();
        result.put("valid", valid);
        return result;
    }
}
