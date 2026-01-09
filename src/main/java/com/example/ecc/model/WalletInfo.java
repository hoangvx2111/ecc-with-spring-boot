package com.example.ecc.model;

import java.security.PublicKey;
import java.security.PrivateKey;

public class WalletInfo {
    private final String address;
    private final PublicKey publicKey;
    private final PrivateKey privateKey;
    private long balance;

    public WalletInfo(String address, PublicKey publicKey, PrivateKey privateKey, long balance) {
        this.address = address;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.balance = balance;
    }

    public String getAddress() { return address; }
    public PublicKey getPublicKey() { return publicKey; }
    public PrivateKey getPrivateKey() { return privateKey; }
    public long getBalance() { return balance; }
    public void setBalance(long balance) { this.balance = balance; }
}
