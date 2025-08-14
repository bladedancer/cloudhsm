package com.matthews.poc.cloudhsm.provider.userprovider;

import lombok.SneakyThrows;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import java.net.Socket;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class MTLSKeyManager extends X509ExtendedKeyManager {
    private String alias;
    private X509Certificate[] chain;
    private PrivateKey key;

    public MTLSKeyManager(Provider provider, String alias) {
        loadKey(provider, alias);
    }

    @SneakyThrows
    private void loadKey(Provider provider, String alias) {
        KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
        keyStore.load(null, null);
        String privateKeyLabel = alias + ":Private";

//        key = (PrivateKey) keyStore.getKey(privateKeyLabel, null);
//        if (key != null) {
//            this.alias = privateKeyLabel;
//            chain = loadCertChain(keyStore, privateKeyLabel);
//        }

        if (key == null) {
            key = (PrivateKey) keyStore.getKey(alias, null);
            if (key != null) {
                this.alias = alias;
                chain = loadCertChain(keyStore, alias);
            }
        }

        if (key == null) {
            // List available aliases for debugging
            java.util.Enumeration<String> aliases = keyStore.aliases();
            StringBuilder availableAliases = new StringBuilder();
            while (aliases.hasMoreElements()) {
                availableAliases.append(aliases.nextElement()).append(", ");
            }
            throw new RuntimeException("Private key not found in CloudHSM. Tried: " + privateKeyLabel + " and " + alias +
                    ". Available aliases: " + availableAliases.toString());
        }
    }

    @SneakyThrows
    private X509Certificate[] loadCertChain(KeyStore keyStore, String alias) {
        Certificate[] certs = keyStore.getCertificateChain(alias);
        if (certs != null && certs.length > 0 && certs[0] instanceof X509Certificate && !(certs instanceof X509Certificate[])) {
            Certificate[] tmp = new X509Certificate[certs.length];
            System.arraycopy(certs, 0, tmp, 0, certs.length);
            certs = tmp;
        }
        return (X509Certificate[]) certs;
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return new String[]{alias};
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return alias;
    }

    @Override
    public String chooseEngineClientAlias(String[] keyType,
                                          Principal[] issuers, SSLEngine engine) {
        return alias;
    }

    @Override
    public String chooseEngineServerAlias(String keyType,
                                          Principal[] issuers, SSLEngine engine) {
        return alias;
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return new String[]{alias};
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return alias;
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        return chain;
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        return key;
    }
}
