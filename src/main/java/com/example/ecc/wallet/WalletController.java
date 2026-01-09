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
    private final Map<String, WalletInfo> walletStore = new ConcurrentHashMap<>();

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
        long initialBalance = 1000L;
        walletStore.put(address,  new WalletInfo(address, keyPair.getPublic(), keyPair.getPrivate(), initialBalance));

        Map<String, String> result = new HashMap<>();
        result.put("address", address);
        result.put("publicKey", Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        return result;
    }

    // 2. List all wallet
    @GetMapping("/list")
    public List<Map<String, Object>> listWallets() {
        List<Map<String, Object>> result = new ArrayList<>();
        for (WalletInfo wallet : walletStore.values()) {
            Map<String, Object> mapData = new HashMap<>();
            mapData.put("address", wallet.getAddress());
            mapData.put("publicKey", Base64.getEncoder().encodeToString(wallet.getPublicKey().getEncoded()));
            result.add(mapData);
        }
        return result;
    }

    // 3. Create wallet sign
    @PostMapping("/sign")
    public Map<String, String> signData(@RequestBody Map<String, String> req) throws Exception {
        String address = req.get("address");
        String data = req.get("data");
        WalletInfo walletInfo = walletStore.get(address);
        if (walletInfo == null) throw new IllegalArgumentException("Wallet not found");

        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaSign.initSign(walletInfo.getPrivateKey());
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
        WalletInfo walletInfo = walletStore.get(address);
        if (walletInfo == null) throw new IllegalArgumentException("Wallet not found");

        Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaVerify.initVerify(walletInfo.getPublicKey());
        ecdsaVerify.update(data.getBytes());
        boolean valid = ecdsaVerify.verify(Base64.getDecoder().decode(signatureB64));

        Map<String, Object> result = new HashMap<>();
        result.put("valid", valid);
        return result;
    }

    // wallet transfer
    @PostMapping("/transfer")
    public Map<String, Object> transfer(@RequestBody Map<String, Object> req) {
        String from = (String) req.get("from");
        String to = (String) req.get("to");
        Number amountNum = (Number) req.get("amount");
        long amount = amountNum.longValue();

        WalletInfo fromWallet = walletStore.get(from);
        WalletInfo toWallet = walletStore.get(to);

        if (fromWallet == null || toWallet == null) throw new IllegalArgumentException("Wallet not found");
        if (amount <= 0) throw new IllegalArgumentException("Amount must be positive");
        if (fromWallet.getBalance() < amount) throw new IllegalArgumentException("Insufficient balance");

        fromWallet.setBalance(fromWallet.getBalance() - amount);
        toWallet.setBalance(toWallet.getBalance() + amount);

        Map<String, Object> result = new HashMap<>();
        result.put("from", from);
        result.put("to", to);
        result.put("amount", amount);
        result.put("fromBalance", fromWallet.getBalance());
        result.put("toBalance", toWallet.getBalance());
        result.put("message", req.get("message"));
        return result;
    }

    // Get wallet balance
    @GetMapping("/balance")
    public Map<String, Object> getBalance(@RequestParam String address) {
        WalletInfo wallet = walletStore.get(address);
        if (wallet == null) throw new IllegalArgumentException("Wallet not found");
        Map<String, Object> result = new HashMap<>();
        result.put("address", address);
        result.put("balance", wallet.getBalance());
        return result;
    }

}
